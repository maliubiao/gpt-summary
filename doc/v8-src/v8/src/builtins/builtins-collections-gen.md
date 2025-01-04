Response: The user wants a summary of the C++ source code file `v8/src/builtins/builtins-collections-gen.cc`.
The file seems to be part of the V8 JavaScript engine, specifically dealing with built-in functions for collections like Map and Set.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core functionality:** The file name suggests it deals with "builtins-collections-gen". The includes confirm this, referencing things like `builtins-constructor-gen.h`, `builtins-iterator-gen.h`, `js-collection.h`, and `ordered-hash-table.h`. This points to the file implementing the core logic for JavaScript's built-in collection types.

2. **Pinpoint key classes and templates:** The code uses a template `TVariable` and defines a base class `BaseCollectionsAssembler` and a derived class `CollectionsBuiltinsAssembler`. These classes likely contain the core implementation logic. The `Variant` enum is used to distinguish between Map, Set, WeakMap, and WeakSet.

3. **Analyze prominent functions:**  The code includes functions like `AddConstructorEntry`, `AddConstructorEntries`, `GenerateConstructor`, `GetAddFunction`, and functions related to table allocation (`AllocateTable`). These functions clearly handle the creation and initialization of collection objects. The presence of "Constructor" in many function names reinforces this idea.

4. **Recognize interaction with JavaScript:** The summary needs to highlight the connection to JavaScript. The file deals with *builtins*, which are the implementations of JavaScript's standard library. The `GenerateConstructor` function is a strong indicator of this, as it's directly involved in creating JavaScript `Map` and `Set` objects. The code also uses terms like "JSArray" and interacts with iterators, both central to JavaScript's collection handling.

5. **Look for optimization strategies:** The code mentions "fast paths" and checks for "FastJSArray". This indicates that the implementation includes optimizations for common use cases, like initializing collections from plain JavaScript arrays.

6. **Identify underlying data structures:** The inclusion of `ordered-hash-table.h` suggests that `Map` and `Set` are implemented using hash tables in V8. The code manipulates these tables directly.

7. **Infer handling of iterators:**  The includes and function names like `AddConstructorEntriesFromIterable` and `IteratorCloseOnException` indicate that the file handles the iteration protocol for collections.

8. **Consider weak collections:** The presence of `WeakMap` and `WeakSet` in the `Variant` enum and function names shows that this file also handles the logic for weak collections.

9. **Formulate the summary points:** Based on the above analysis, the following key functional aspects can be identified:
    * Implementing constructors for `Map`, `Set`, `WeakMap`, and `WeakSet`.
    * Handling initialization with iterable objects.
    * Optimizations for initialization from fast JavaScript arrays.
    * Management of the underlying hash tables.
    * Handling of iterators.
    * Logic for weak collections.

10. **Connect to JavaScript examples:** To illustrate the connection to JavaScript, provide simple examples of creating and initializing `Map` and `Set` objects, showcasing the scenarios the C++ code handles.

11. **Structure the answer:** Organize the summary into clear points and provide the JavaScript examples separately for better readability. Emphasize that this is part 1 of 2, as requested by the user.
这个C++源代码文件 `v8/src/builtins/builtins-collections-gen.cc` 的主要功能是 **为 JavaScript 的内置集合类型（Map, Set, WeakMap, WeakSet）生成和实现其构造函数及相关的内部操作逻辑。**

更具体地说，这部分代码负责处理以下几个关键方面：

1. **构造函数的实现:**  它定义了当在 JavaScript 中使用 `new Map()` 或 `new Set()` 等构造函数时，V8 引擎内部如何创建和初始化这些集合对象。
2. **基于可迭代对象初始化集合:**  它实现了将可迭代对象（例如数组、其他 Map 或 Set）的内容添加到新创建的集合中的逻辑。这包括处理不同类型的可迭代对象，并针对某些常见情况（如初始化自普通的 JavaScript 数组）进行优化。
3. **管理集合的内部数据结构:**  代码涉及到集合内部使用的哈希表（如 `OrderedHashMap` 和 `OrderedHashSet`）的分配和操作。
4. **处理 `add` 操作:**  它定义了向集合中添加元素的内部逻辑，根据集合的类型（Map 或 Set）调用相应的 `add` 或 `set` 方法。
5. **处理弱集合的特殊性:**  对于 `WeakMap` 和 `WeakSet`，它会处理键的弱引用特性。

**与 JavaScript 功能的关系及示例:**

这个 C++ 文件直接实现了 JavaScript 中 `Map`, `Set`, `WeakMap`, 和 `WeakSet` 的行为。当你使用这些集合类型时，V8 引擎会执行这个文件中定义的 C++ 代码。

**JavaScript 示例:**

```javascript
// 创建一个新的 Map
const myMap = new Map();

// 向 Map 中添加键值对
myMap.set('a', 1);
myMap.set('b', 2);

// 创建一个新的 Set
const mySet = new Set();

// 向 Set 中添加元素
mySet.add(1);
mySet.add(2);
mySet.add(1); // Set 中重复的元素会被忽略

// 使用可迭代对象初始化 Map 和 Set
const initialArray = [['key1', 'value1'], ['key2', 'value2']];
const anotherMap = new Map(initialArray);

const initialSetArray = [1, 2, 3, 2];
const anotherSet = new Set(initialSetArray);

// 创建 WeakMap 和 WeakSet (注意键必须是对象)
const key1 = {};
const key2 = {};
const myWeakMap = new WeakMap();
myWeakMap.set(key1, 'weak value 1');
myWeakMap.set(key2, 'weak value 2');

const weakSetValue1 = {};
const weakSetValue2 = {};
const myWeakSet = new WeakSet();
myWeakSet.add(weakSetValue1);
myWeakSet.add(weakSetValue2);
```

在这个 C++ 文件中，你可以找到实现以下 JavaScript 行为的代码：

* 当你调用 `new Map()` 或 `new Set()` 时，`GenerateConstructor` 函数会被调用。
* 当你使用 `myMap.set('a', 1)` 时，涉及到 `GetAddFunction` 获取 `set` 方法，然后调用相应的内部逻辑来将键值对添加到 `myMap` 的内部哈希表中。
* 当你使用 `new Map(initialArray)` 时，`AddConstructorEntries` 函数会遍历 `initialArray` 并将其中的键值对添加到新的 Map 对象中。
* 弱集合的创建和操作也会在这个文件中找到相应的实现逻辑。

总而言之，`builtins-collections-gen.cc` 是 V8 引擎中至关重要的组成部分，它负责将 JavaScript 中抽象的集合概念转化为高效的底层实现。

Prompt: 
```
这是目录为v8/src/builtins/builtins-collections-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

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
  const TNode<Float64T> key_number = SmiToFloat64(key_smi);

  GotoIf(Float64Equal(candidate_key_number, key_number), if_same);

  Goto(if_not_same);
}

void CollectionsBuiltinsAssembler::BranchIfMapIteratorProtectorValid(
    Label* if_true, Label* if_false) {
  TNode<PropertyCell> protector_cell = MapIteratorProtectorConstant();
  DCHECK(i::IsPropertyCell(isolate()->heap()->map_iterator_protector()));
  Branch(
      TaggedEqual(LoadObjectField(protector_cell, PropertyCell::kValueOffset),
                  SmiConstant(Protectors::kProtectorValid)),
      if_true, if_false);
}

void CollectionsBuiltinsAssembler::
    BranchIfIterableWithOriginalKeyOrValueMapIterator(TNode<Object> iterator,
                                                      TNode<Context> context,
                                                      Label* if_true,
                                                      Label* if_false) {
  Label if_key_or_value_iterator(this), extra_checks(this);

  // Check if iterator is a keys or values JSMapIterator.
  GotoIf(TaggedIsSmi(iterator), if_false);
  TNode<Map> iter_map = LoadMap(CAST(iterator));
  const TNode<Uint16T> instance_type = LoadMapInstanceType(iter_map);
  GotoIf(InstanceTypeEqual(instance_type, JS_MAP_KEY_ITERATOR_TYPE),
         &if_key_or_value_iterator);
  Branch(InstanceTypeEqual(instance_type, JS_MAP_VALUE_ITERATOR_TYPE),
         &if_key_or_value_iterator, if_false);

  BIND(&if_key_or_value_iterator);
  // Check that the iterator is not partially consumed.
  const TNode<Object> index =
      LoadObjectField(CAST(iterator), JSMapIterator::kIndexOffset);
  GotoIfNot(TaggedEqual(index, SmiConstant(0)), if_false);
  BranchIfMapIteratorProtectorValid(&extra_checks, if_false);

  BIND(&extra_checks);
  // Check if the iterator object has the original %MapIteratorPrototype%.
  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Object> initial_map_iter_proto = LoadContextElement(
      native_context, Context::INITIAL_MAP_ITERATOR_PROTOTYPE_INDEX);
  const TNode<HeapObject> map_iter_proto = LoadMapPrototype(iter_map);
  GotoIfNot(TaggedEqual(map_iter_proto, initial_map_iter_proto), if_false);

  // Check if the original MapIterator prototype has the original
  // %IteratorPrototype%.
  const TNode<Object> initial_iter_proto = LoadContextElement(
      native_context, Context::INITIAL_ITERATOR_PROTOTYPE_INDEX);
  const TNode<HeapObject> iter_proto =
      LoadMapPrototype(LoadMap(map_iter_proto));
  Branch(TaggedEqual(iter_proto, initial_iter_proto), if_true, if_false);
}

void BranchIfIterableWithOriginalKeyOrValueMapIterator(
    compiler::CodeAssemblerState* state, TNode<Object> iterable,
    TNode<Context> context, compiler::CodeAssemblerLabel* if_true,
    compiler::CodeAssemblerLabel* if_false) {
  CollectionsBuiltinsAssembler assembler(state);
  assembler.BranchIfIterableWithOriginalKeyOrValueMapIterator(
      iterable, context, if_true, if_false);
}

void CollectionsBuiltinsAssembler::BranchIfSetIteratorProtectorValid(
    Label* if_true, Label* if_false) {
  const TNode<PropertyCell> protector_cell = SetIteratorProtectorConstant();
  DCHECK(i::IsPropertyCell(isolate()->heap()->set_iterator_protector()));
  Branch(
      TaggedEqual(LoadObjectField(protector_cell, PropertyCell::kValueOffset),
                  SmiConstant(Protectors::kProtectorValid)),
      if_true, if_false);
}

void CollectionsBuiltinsAssembler::BranchIfIterableWithOriginalValueSetIterator(
    TNode<Object> iterable, TNode<Context> context, Label* if_true,
    Label* if_false) {
  Label if_set(this), if_value_iterator(this), check_protector(this);
  TVARIABLE(BoolT, var_result);

  GotoIf(TaggedIsSmi(iterable), if_false);
  TNode<Map> iterable_map = LoadMap(CAST(iterable));
  const TNode<Uint16T> instance_type = LoadMapInstanceType(iterable_map);

  GotoIf(InstanceTypeEqual(instance_type, JS_SET_TYPE), &if_set);
  Branch(InstanceTypeEqual(instance_type, JS_SET_VALUE_ITERATOR_TYPE),
         &if_value_iterator, if_false);

  BIND(&if_set);
  // Check if the set object has the original Set prototype.
  const TNode<Object> initial_set_proto = LoadContextElement(
      LoadNativeContext(context), Context::INITIAL_SET_PROTOTYPE_INDEX);
  const TNode<HeapObject> set_proto = LoadMapPrototype(iterable_map);
  GotoIfNot(TaggedEqual(set_proto, initial_set_proto), if_false);
  Goto(&check_protector);

  BIND(&if_value_iterator);
  // Check that the iterator is not partially consumed.
  const TNode<Object> index =
      LoadObjectField(CAST(iterable), JSSetIterator::kIndexOffset);
  GotoIfNot(TaggedEqual(index, SmiConstant(0)), if_false);

  // Check if the iterator object has the original SetIterator prototype.
  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Object> initial_set_iter_proto = LoadContextElement(
      native_context, Context::INITIAL_SET_ITERATOR_PROTOTYPE_INDEX);
  const TNode<HeapObject> set_iter_proto = LoadMapPrototype(iterable_map);
  GotoIfNot(TaggedEqual(set_iter_proto, initial_set_iter_proto), if_false);

  // Check if the original SetIterator prototype has the original
  // %IteratorPrototype%.
  const TNode<Object> initial_iter_proto = LoadContextElement(
      native_context, Context::INITIAL_ITERATOR_PROTOTYPE_INDEX);
  const TNode<HeapObject> iter_proto =
      LoadMapPrototype(LoadMap(set_iter_proto));
  GotoIfNot(TaggedEqual(iter_proto, initial_iter_proto), if_false);
  Goto(&check_protector);

  BIND(&check_protector);
  BranchIfSetIteratorProtectorValid(if_true, if_false);
}

void BranchIfIterableWithOriginalValueSetIterator(
    compiler::CodeAssemblerState* state, TNode<Object> iterable,
    TNode<Context> context, compiler::CodeAssemblerLabel* if_true,
    compiler::CodeAssemblerLabel* if_false) {
  CollectionsBuiltinsAssembler assembler(state);
  assembler.BranchIfIterableWithOriginalValueSetIterator(iterable, context,
                                                         if_true, if_false);
}

// A helper function to help extract the {table} from either a Set or
// SetIterator. The function has a side effect of marking the
// SetIterator (if SetIterator is passed) as exhausted.
TNode<OrderedHashSet> CollectionsBuiltinsAssembler::SetOrSetIteratorToSet(
    TNode<Object> iterable) {
  TVARIABLE(OrderedHashSet, var_table);
  Label if_set(this), if_iterator(this), done(this);

  const TNode<Uint16T> instance_type = LoadInstanceType(CAST(iterable));
  Branch(InstanceTypeEqual(instance_type, JS_SET_TYPE), &if_set, &if_iterator);

  BIND(&if_set);
  {
    // {iterable} is a JSSet.
    var_table = LoadObjectField<OrderedHashSet>(CAST(iterable),
                                                GetTableOffset(Variant::kSet));
    Goto(&done);
  }

  BIND(&if_iterator);
  {
    // {iterable} is a JSSetIterator.
    // Transition the {iterable} table if necessary.
    TNode<JSSetIterator> iterator = CAST(iterable);
    TNode<OrderedHashSet> table;
    TNode<IntPtrT> index;
    std::tie(table, index) =
        TransitionAndUpdate<JSSetIterator, OrderedHashSet>(iterator);
    CSA_DCHECK(this, IntPtrEqual(index, IntPtrConstant(0)));
    var_table = table;
    // Set the {iterable} to exhausted if it's an iterator.
    StoreObjectFieldRoot(iterator, JSSetIterator::kTableOffset,
                         RootIndex::kEmptyOrderedHashSet);
    TNode<IntPtrT> number_of_elements = LoadAndUntagPositiveSmiObjectField(
        table, OrderedHashSet::NumberOfElementsOffset());
    StoreObjectFieldNoWriteBarrier(iterator, JSSetIterator::kIndexOffset,
                                   SmiTag(number_of_elements));
    Goto(&done);
  }

  BIND(&done);
  return var_table.value();
}

TNode<JSArray> CollectionsBuiltinsAssembler::MapIteratorToList(
    TNode<Context> context, TNode<JSMapIterator> iterator) {
  // Transition the {iterator} table if necessary.
  TNode<OrderedHashMap> table;
  TNode<IntPtrT> index;
  std::tie(table, index) =
      TransitionAndUpdate<JSMapIterator, OrderedHashMap>(iterator);
  CSA_DCHECK(this, IntPtrEqual(index, IntPtrConstant(0)));

  TNode<Smi> size_smi =
      LoadObjectField<Smi>(table, OrderedHashMap::NumberOfElementsOffset());
  TNode<IntPtrT> size = PositiveSmiUntag(size_smi);

  const ElementsKind kind = PACKED_ELEMENTS;
  TNode<Map> array_map =
      LoadJSArrayElementsMap(kind, LoadNativeContext(context));
  TNode<JSArray> array = AllocateJSArray(kind, array_map, size, size_smi);
  TNode<FixedArray> elements = CAST(LoadElements(array));

  const int first_element_offset =
      OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag;
  TNode<IntPtrT> first_to_element_offset =
      ElementOffsetFromIndex(IntPtrConstant(0), kind, 0);
  TVARIABLE(
      IntPtrT, var_offset,
      IntPtrAdd(first_to_element_offset, IntPtrConstant(first_element_offset)));
  TVARIABLE(IntPtrT, var_index, index);
  VariableList vars({&var_index, &var_offset}, zone());
  Label done(this, {&var_index}), loop(this, vars), continue_loop(this, vars),
      write_key(this, vars), write_value(this, vars);

  Goto(&loop);

  BIND(&loop);
  {
    // Read the next entry from the {table}, skipping holes.
    TNode<Object> entry_key;
    TNode<IntPtrT> entry_start_position;
    TNode<IntPtrT> cur_index;
    std::tie(entry_key, entry_start_position, cur_index) =
        NextSkipHashTableHoles<OrderedHashMap>(table, var_index.value(), &done);

    // Decide to write key or value.
    Branch(
        InstanceTypeEqual(LoadInstanceType(iterator), JS_MAP_KEY_ITERATOR_TYPE),
        &write_key, &write_value);

    BIND(&write_key);
    {
      Store(elements, var_offset.value(), entry_key);
      Goto(&continue_loop);
    }

    BIND(&write_value);
    {
      CSA_DCHECK(this, InstanceTypeEqual(LoadInstanceType(iterator),
                                         JS_MAP_VALUE_ITERATOR_TYPE));
      TNode<Object> entry_value =
          UnsafeLoadValueFromOrderedHashMapEntry(table, entry_start_position);

      Store(elements, var_offset.value(), entry_value);
      Goto(&continue_loop);
    }

    BIND(&continue_loop);
    {
      // Increment the array offset and continue the loop to the next entry.
      var_index = cur_index;
      var_offset = IntPtrAdd(var_offset.value(), IntPtrConstant(kTaggedSize));
      Goto(&loop);
    }
  }

  BIND(&done);
  // Set the {iterator} to exhausted.
  StoreObjectFieldRoot(iterator, JSMapIterator::kTableOffset,
                       RootIndex::kEmptyOrderedHashMap);
  StoreObjectFieldNoWriteBarrier(iterator, JSMapIterator::kIndexOffset,
                                 SmiTag(var_index.value()));
  return UncheckedCast<JSArray>(array);
}

TF_BUILTIN(MapIteratorToList, CollectionsBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto iterator = Parameter<JSMapIterator>(Descriptor::kSource);
  Return(MapIteratorToList(context, iterator));
}

TNode<JSArray> CollectionsBuiltinsAssembler::SetOrSetIteratorToList(
    TNode<Context> context, TNode<HeapObject> iterable) {
  TNode<OrderedHashSet> table = SetOrSetIteratorToSet(iterable);
  TNode<Smi> size_smi =
      LoadObjectField<Smi>(table, OrderedHashMap::NumberOfElementsOffset());
  TNode<IntPtrT> size = PositiveSmiUntag(size_smi);

  const ElementsKind kind = PACKED_ELEMENTS;
  TNode<Map> array_map =
      LoadJSArrayElementsMap(kind, LoadNativeContext(context));
  TNode<JSArray> array = AllocateJSArray(kind, array_map, size, size_smi);
  TNode<FixedArray> elements = CAST(LoadElements(array));

  const int first_element_offset =
      OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag;
  TNode<IntPtrT> first_to_element_offset =
      ElementOffsetFromIndex(IntPtrConstant(0), kind, 0);
  TVARIABLE(
      IntPtrT, var_offset,
      IntPtrAdd(first_to_element_offset, IntPtrConstant(first_element_offset)));
  TVARIABLE(IntPtrT, var_index, IntPtrConstant(0));
  Label done(this), loop(this, {&var_index, &var_offset});

  Goto(&loop);

  BIND(&loop);
  {
    // Read the next entry from the {table}, skipping holes.
    TNode<Object> entry_key;
    TNode<IntPtrT> entry_start_position;
    TNode<IntPtrT> cur_index;
    std::tie(entry_key, entry_start_position, cur_index) =
        NextSkipHashTableHoles<OrderedHashSet>(table, var_index.value(), &done);

    Store(elements, var_offset.value(), entry_key);

    var_index = cur_index;
    var_offset = IntPtrAdd(var_offset.value(), IntPtrConstant(kTaggedSize));
    Goto(&loop);
  }

  BIND(&done);
  return UncheckedCast<JSArray>(array);
}

TF_BUILTIN(SetOrSetIteratorToList, CollectionsBuiltinsAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto object = Parameter<HeapObject>(Descriptor::kSource);
  Return(SetOrSetIteratorToList(context, object));
}

TNode<Word32T> CollectionsBuiltinsAssembler::ComputeUnseededHash(
    TNode<IntPtrT> key) {
  // See v8::internal::ComputeUnseededHash()
  TNode<Word32T> hash = TruncateIntPtrToInt32(key);
  hash = Int32Add(Word32Xor(hash, Int32Constant(0xFFFFFFFF)),
                  Word32Shl(hash, Int32Constant(15)));
  hash = Word32Xor(hash, Word32Shr(hash, Int32Constant(12)));
  hash = Int32Add(hash, Word32Shl(hash, Int32Constant(2)));
  hash = Word32Xor(hash, Word32Shr(hash, Int32Constant(4)));
  hash = Int32Mul(hash, Int32Constant(2057));
  hash = Word32Xor(hash, Word32Shr(hash, Int32Constant(16)));
  return Word32And(hash, Int32Constant(0x3FFFFFFF));
}

template <typename CollectionType>
void CollectionsBuiltinsAssembler::FindOrderedHashTableEntryForSmiKey(
    TNode<CollectionType> table, TNode<Smi> smi_key, TVariable<IntPtrT>* result,
    Label* entry_found, Label* not_found) {
  const TNode<IntPtrT> key_untagged = SmiUntag(smi_key);
  const TNode<Uint32T> hash = Unsigned(ComputeUnseededHash(key_untagged));
  *result = Signed(ChangeUint32ToWord(hash));
  FindOrderedHashTableEntry<CollectionType>(
      table, hash,
      [&](TNode<Object> other_key, Label* if_same, Label* if_not_same) {
        SameValueZeroSmi(smi_key, other_key, if_same, if_not_same);
      },
      result, entry_found, not_found);
}

template <typename CollectionType>
void CollectionsBuiltinsAssembler::FindOrderedHashTableEntryForStringKey(
    TNode<CollectionType> table, TNode<String> key_tagged,
    TVariable<IntPtrT>* result, Label* entry_found, Label* not_found) {
  const TNode<Uint32T> hash = ComputeStringHash(key_tagged);
  *result = Signed(ChangeUint32ToWord(hash));
  FindOrderedHashTableEntry<CollectionType>(
      table, hash,
      [&](TNode<Object> other_key, Label* if_same, Label* if_not_same) {
        SameValueZeroString(key_tagged, other_key, if_same, if_not_same);
      },
      result, entry_found, not_found);
}

template <typename CollectionType>
void CollectionsBuiltinsAssembler::FindOrderedHashTableEntryForHeapNumberKey(
    TNode<CollectionType> table, TNode<HeapNumber> key_heap_number,
    TVariable<IntPtrT>* result, Label* entry_found, Label* not_found) {
  const TNode<Uint32T> hash = CallGetHashRaw(key_heap_number);
  *result = Signed(ChangeUint32ToWord(hash));
  const TNode<Float64T> key_float = LoadHeapNumberValue(key_heap_number);
  FindOrderedHashTableEntry<CollectionType>(
      table, hash,
      [&](TNode<Object> other_key, Label* if_same, Label* if_not_same) {
        SameValueZeroHeapNumber(key_float, other_key, if_same, if_not_same);
      },
      result, entry_found, not_found);
}

template <typename CollectionType>
void CollectionsBuiltinsAssembler::FindOrderedHashTableEntryForBigIntKey(
    TNode<CollectionType> table, TNode<BigInt> key_big_int,
    TVariable<IntPtrT>* result, Label* entry_found, Label* not_found) {
  const TNode<Uint32T> hash = CallGetHashRaw(key_big_int);
  *result = Signed(ChangeUint32ToWord(hash));
  FindOrderedHashTableEntry<CollectionType>(
      table, hash,
      [&](TNode<Object> other_key, Label* if_same, Label* if_not_same) {
        SameValueZeroBigInt(key_big_int, other_key, if_same, if_not_same);
      },
      result, entry_found, not_found);
}

template <typename CollectionType>
void CollectionsBuiltinsAssembler::FindOrderedHashTableEntryForOtherKey(
    TNode<CollectionType> table, TNode<HeapObject> key_heap_object,
    TVariable<IntPtrT>* result, Label* entry_found, Label* not_found) {
  const TNode<Uint32T> hash = GetHash(key_heap_object);
  *result = Signed(ChangeUint32ToWord(hash));
  FindOrderedHashTableEntry<CollectionType>(
      table, hash,
      [&](TNode<Object> other_key, Label* if_same, Label* if_not_same) {
        Branch(TaggedEqual(key_heap_object, other_key), if_same, if_not_same);
      },
      result, entry_found, not_found);
}

TNode<Uint32T> CollectionsBuiltinsAssembler::ComputeStringHash(
    TNode<String> string_key) {
  TVARIABLE(Uint32T, var_result);

  Label hash_not_computed(this), done(this, &var_result);
  const TNode<Uint32T> hash = LoadNameHash(string_key, &hash_not_computed);
  var_result = hash;
  Goto(&done);

  BIND(&hash_not_computed);
  var_result = CallGetHashRaw(string_key);
  Goto(&done);

  BIND(&done);
  return var_result.value();
}

void CollectionsBuiltinsAssembler::SameValueZeroString(
    TNode<String> key_string, TNode<Object> candidate_key, Label* if_same,
    Label* if_not_same) {
  // If the candidate is not a string, the keys are not equal.
  GotoIf(TaggedIsSmi(candidate_key), if_not_same);
  GotoIfNot(IsString(CAST(candidate_key)), if_not_same);

  GotoIf(TaggedEqual(key_string, candidate_key), if_same);
  BranchIfStringEqual(key_string, CAST(candidate_key), if_same, if_not_same);
}

void CollectionsBuiltinsAssembler::SameValueZeroBigInt(
    TNode<BigInt> key, TNode<Object> candidate_key, Label* if_same,
    Label* if_not_same) {
  GotoIf(TaggedIsSmi(candidate_key), if_not_same);
  GotoIfNot(IsBigInt(CAST(candidate_key)), if_not_same);

  Branch(TaggedEqual(CallRuntime(Runtime::kBigIntEqualToBigInt,
                                 NoContextConstant(), key, candidate_key),
                     TrueConstant()),
         if_same, if_not_same);
}

void CollectionsBuiltinsAssembler::SameValueZeroHeapNumber(
    TNode<Float64T> key_float, TNode<Object> candidate_key, Label* if_same,
    Label* if_not_same) {
  Label if_smi(this), if_keyisnan(this);

  GotoIf(TaggedIsSmi(candidate_key), &if_smi);
  GotoIfNot(IsHeapNumber(CAST(candidate_key)), if_not_same);

  {
    // {candidate_key} is a heap number.
    const TNode<Float64T> candidate_float =
        LoadHeapNumberValue(CAST(candidate_key));
    GotoIf(Float64Equal(key_float, candidate_float), if_same);

    // SameValueZero needs to treat NaNs as equal. First check if {key_float}
    // is NaN.
    BranchIfFloat64IsNaN(key_float, &if_keyisnan, if_not_same);

    BIND(&if_keyisnan);
    {
      // Return true iff {candidate_key} is NaN.
      Branch(Float64Equal(candidate_float, candidate_float), if_not_same,
             if_same);
    }
  }

  BIND(&if_smi);
  {
    const TNode<Float64T> candidate_float = SmiToFloat64(CAST(candidate_key));
    Branch(Float64Equal(key_float, candidate_float), if_same, if_not_same);
  }
}

TF_BUILTIN(OrderedHashTableHealIndex, CollectionsBuiltinsAssembler) {
  auto table = Parameter<HeapObject>(Descriptor::kTable);
  auto index = Parameter<Smi>(Descriptor::kIndex);
  Label return_index(this), return_zero(this);

  // Check if we need to update the {index}.
  GotoIfNot(SmiLessThan(SmiConstant(0), index), &return_zero);

  // Check if the {table} was cleared.
  static_assert(OrderedHashMap::NumberOfDeletedElementsOffset() ==
                OrderedHashSet::NumberOfDeletedElementsOffset());
  TNode<Int32T> number_of_deleted_elements = LoadAndUntagToWord32ObjectField(
      table, OrderedHashMap::NumberOfDeletedElementsOffset());
  static_assert(OrderedHashMap::kClearedTableSentinel ==
                OrderedHashSet::kClearedTableSentinel);
  GotoIf(Word32Equal(number_of_deleted_elements,
                     Int32Constant(OrderedHashMap::kClearedTableSentinel)),
         &return_zero);

  TVARIABLE(Int32T, var_i, Int32Constant(0));
  TVARIABLE(Smi, var_index, index);
  Label loop(this, {&var_i, &var_index});
  Goto(&loop);
  BIND(&loop);
  {
    TNode<Int32T> i = var_i.value();
    GotoIfNot(Int32LessThan(i, number_of_deleted_elements), &return_index);
    static_assert(OrderedHashMap::RemovedHolesIndex() ==
                  OrderedHashSet::RemovedHolesIndex());
    TNode<Smi> removed_index = CAST(LoadFixedArrayElement(
        CAST(table), ChangeUint32ToWord(i),
        OrderedHashMap::RemovedHolesIndex() * kTaggedSize));
    GotoIf(SmiGreaterThanOrEqual(removed_index, index), &return_index);
    Decrement(&var_index);
    var_i = Int32Add(var_i.value(), Int32Constant(1));
    Goto(&loop);
  }

  BIND(&return_index);
  Return(var_index.value());

  BIND(&return_zero);
  Return(SmiConstant(0));
}

template <typename TableType>
std::pair<TNode<TableType>, TNode<IntPtrT>>
CollectionsBuiltinsAssembler::Transition(
    const TNode<TableType> table, const TNode<IntPtrT> index,
    UpdateInTransition<TableType> const& update_in_transition) {
  TVARIABLE(IntPtrT, var_index, index);
  TVARIABLE(TableType, var_table, table);
  Label if_done(this), if_transition(this, Label::kDeferred);
  Branch(TaggedIsSmi(
             LoadObjectField(var_table.value(), TableType::NextTableOffset())),
         &if_done, &if_transition);

  BIND(&if_transition);
  {
    Label loop(this, {&var_table, &var_index}), done_loop(this);
    Goto(&loop);
    BIND(&loop);
    {
      TNode<TableType> current_table = var_table.value();
      TNode<IntPtrT> current_index = var_index.value();

      TNode<Object> next_table =
          LoadObjectField(current_table, TableType::NextTableOffset());
      GotoIf(TaggedIsSmi(next_table), &done_loop);

      var_table = CAST(next_table);
      var_index = SmiUntag(CAST(CallBuiltin(Builtin::kOrderedHashTableHealIndex,
                                            NoContextConstant(), current_table,
                                            SmiTag(current_index))));
      Goto(&loop);
    }
    BIND(&done_loop);

    // Update with the new {table} and {index}.
    update_in_transition(var_table.value(), var_index.value());
    Goto(&if_done);
  }

  BIND(&if_done);
  return {var_table.value(), var_index.value()};
}

template <typename IteratorType, typename TableType>
std::pair<TNode<TableType>, TNode<IntPtrT>>
CollectionsBuiltinsAssembler::TransitionAndUpdate(
    const TNode<IteratorType> iterator) {
  return Transition<TableType>(
      CAST(LoadObjectField(iterator, IteratorType::kTableOffset)),
      LoadAndUntagPositiveSmiObjectField(iterator, IteratorType::kIndexOffset),
      [this, iterator](const TNode<TableType> table,
                       const TNode<IntPtrT> index) {
        // Update the {iterator} with the new state.
        StoreObjectField(iterator, IteratorType::kTableOffset, table);
        StoreObjectFieldNoWriteBarrier(iterator, IteratorType::kIndexOffset,
                                       SmiTag(index));
      });
}

TorqueStructOrderedHashSetIndexPair
CollectionsBuiltinsAssembler::TransitionOrderedHashSetNoUpdate(
    const TNode<OrderedHashSet> table_arg, const TNode<IntPtrT> index_arg) {
  TNode<OrderedHashSet> table;
  TNode<IntPtrT> index;
  std::tie(table, index) = Transition<OrderedHashSet>(
      table_arg, index_arg,
      [](const TNode<OrderedHashSet>, const TNode<IntPtrT>) {});
  return TorqueStructOrderedHashSetIndexPair{table, index};
}

template <typename TableType>
std::tuple<TNode<Object>, TNode<IntPtrT>, TNode<IntPtrT>>
CollectionsBuiltinsAssembler::NextSkipHashTableHoles(TNode<TableType> table,
                                                     TNode<IntPtrT> index,
                                                     Label* if_end) {
  // Compute the used capacity for the {table}.
  TNode<Int32T> number_of_buckets = LoadAndUntagToWord32ObjectField(
      table, TableType::NumberOfBucketsOffset());
  TNode<Int32T> number_of_elements = LoadAndUntagToWord32ObjectField(
      table, TableType::NumberOfElementsOffset());
  TNode<Int32T> number_of_deleted_elements = LoadAndUntagToWord32ObjectField(
      table, TableType::NumberOfDeletedElementsOffset());
  TNode<Int32T> used_capacity =
      Int32Add(number_of_elements, number_of_deleted_elements);

  return NextSkipHashTableHoles(table, number_of_buckets, used_capacity, index,
                                if_end);
}

template <typename TableType>
std::tuple<TNode<Object>, TNode<IntPtrT>, TNode<IntPtrT>>
CollectionsBuiltinsAssembler::NextSkipHashTableHoles(
    TNode<TableType> table, TNode<Int32T> number_of_buckets,
    TNode<Int32T> used_capacity, TNode<IntPtrT> index, Label* if_end) {
  CSA_DCHECK(this, Word32Equal(number_of_buckets,
                               LoadAndUntagToWord32ObjectField(
                                   table, TableType::NumberOfBucketsOffset())));
  CSA_DCHECK(
      this,
      Word32Equal(
          used_capacity,
          Int32Add(LoadAndUntagToWord32ObjectField(
                       table, TableType::NumberOfElementsOffset()),
                   LoadAndUntagToWord32ObjectField(
                       table, TableType::NumberOfDeletedElementsOffset()))));

  TNode<Object> entry_key;
  TNode<Int32T> entry_start_position;
  TVARIABLE(Int32T, var_index, TruncateIntPtrToInt32(index));
  Label loop(this, &var_index), done_loop(this);
  Goto(&loop);
  BIND(&loop);
  {
    GotoIfNot(Int32LessThan(var_index.value(), used_capacity), if_end);
    entry_start_position = Int32Add(
        Int32Mul(var_index.value(), Int32Constant(TableType::kEntrySize)),
        number_of_buckets);
    entry_key = UnsafeLoadKeyFromOrderedHashTableEntry(
        table, ChangePositiveInt32ToIntPtr(entry_start_position));
    var_index = Int32Add(var_index.value(), Int32Constant(1));
    Branch(IsHashTableHole(entry_key), &loop, &done_loop);
  }

  BIND(&done_loop);
  return std::tuple<TNode<Object>, TNode<IntPtrT>, TNode<IntPtrT>>{
      entry_key, ChangePositiveInt32ToIntPtr(entry_start_position),
      ChangePositiveInt32ToIntPtr(var_index.value())};
}

template <typename CollectionType>
TorqueStructKeyIndexPair
CollectionsBuiltinsAssembler::NextKeyIndexPairUnmodifiedTable(
    const TNode<CollectionType> table, const TNode<Int32T> number_of_buckets,
    const TNode<Int32T> used_capacity, const TNode<IntPtrT> index,
    Label* if_end) {
  // Unmodified tables do not have transitions.
  CSA_DCHECK(this, TaggedIsSmi(LoadObjectField(
                       table, CollectionType::NextTableOffset())));

  TNode<Object> key;
  TNode<IntPtrT> entry_start_position;
  TNode<IntPtrT> next_index;

  std::tie(key, entry_start_position, next_index) = NextSkipHashTableHoles(
      table, number_of_buckets, used_capacity, index, if_end);

  return TorqueStructKeyIndexPair{key, next_index};
}

template TorqueStructKeyIndexPair
CollectionsBuiltinsAssembler::NextKeyIndexPairUnmodifiedTable(
    const TNode<OrderedHashMap> table, const TNode<Int32T> number_of_buckets,
    const TNode<Int32T> used_capacity, const TNode<IntPtrT> index,
    Label* if_end);
template TorqueStructKeyIndexPair
CollectionsBuiltinsAssembler::NextKeyIndexPairUnmodifiedTable(
    const TNode<OrderedHashSet> table, const TNode<Int32T> number_of_buckets,
    const TNode<Int32T> used_capacity, const TNode<IntPtrT> index,
    Label* if_end);

template <typename CollectionType>
TorqueStructKeyIndexPair CollectionsBuiltinsAssembler::NextKeyIndexPair(
    const TNode<CollectionType> table, const TNode<IntPtrT> index,
    Label* if_end) {
  TNode<Object> key;
  TNode<IntPtrT> entry_start_position;
  TNode<IntPtrT> next_index;

  std::tie(key, entry_start_position, next_index) =
      NextSkipHashTableHoles<CollectionType>(table, index, if_end);

  return TorqueStructKeyIndexPair{key, next_index};
}

template TorqueStructKeyIndexPair
CollectionsBuiltinsAssembler::NextKeyIndexPair(
    const TNode<OrderedHashMap> table, const TNode<IntPtrT> index,
    Label* if_end);
template TorqueStructKeyIndexPair
CollectionsBuiltinsAssembler::NextKeyIndexPair(
    const TNode<OrderedHashSet> table, const TNode<IntPtrT> index,
    Label* if_end);

TorqueStructKeyValueIndexTuple
CollectionsBuiltinsAssembler::NextKeyValueIndexTupleUnmodifiedTable(
    const TNode<OrderedHashMap> table, const TNode<Int32T> number_of_buckets,
    const TNode<Int32T> used_capacity, const TNode<IntPtrT> index,
    Label* if_end) {
  TNode<Object> key;
  TNode<IntPtrT> entry_start_position;
  TNode<IntPtrT> next_index;

  std::tie(key, entry_start_position, next_index) = NextSkipHashTableHoles(
      table, number_of_buckets, used_capacity, index, if_end);

  TNode<Object> value =
      UnsafeLoadValueFromOrderedHashMapEntry(table, entry_start_position);

  return TorqueStructKeyValueIndexTuple{key, value, next_index};
}

TorqueStructKeyValueIndexTuple
CollectionsBuiltinsAssembler::NextKeyValueIndexTuple(
    const TNode<OrderedHashMap> table, const TNode<IntPtrT> index,
    Label* if_end) {
  TNode<Object> key;
  TNode<IntPtrT> entry_start_position;
  TNode<IntPtrT> next_index;

  std::tie(key, entry_start_position, next_index) =
      NextSkipHashTableHoles(table, index, if_end);

  TNode<Object> value =
      UnsafeLoadValueFromOrderedHashMapEntry(table, entry_start_position);

  return TorqueStructKeyValueIndexTuple{key, value, next_index};
}

TF_BUILTIN(MapPrototypeGet, CollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto key = Parameter<Object>(Descriptor::kKey);
  const auto context = Parameter<Context>(Descriptor::kContext);

  ThrowIfNotInstanceType(context, receiver, JS_MAP_TYPE, "Map.prototype.get");

  const TNode<Object> table =
      LoadObjectField<Object>(CAST(receiver), JSMap::kTableOffset);
  TNode<Smi> index =
      CAST(CallBuiltin(Builtin::kFindOrderedHashMapEntry, context, table, key));

  Label if_found(this), if_not_found(this);
  Branch(SmiGreaterThanOrEqual(index, SmiConstant(0)), &if_found,
         &if_not_found);

  BIND(&if_found);
  Return(LoadValueFromOrderedHashMapEntry(CAST(table), SmiUntag(index)));

  BIND(&if_not_found);
  Return(UndefinedConstant());
}

TF_BUILTIN(MapPrototypeHas, CollectionsBuiltinsAssembler) {
  const auto receiver = Parameter<Object>(Descriptor::kReceiver);
  const auto key = Parameter<Object>(Descriptor::kKey);
  const auto context = Parameter<Context>(Descriptor::kContext);

  ThrowIfNotInstanceType(context, receiver, JS_MAP_TYPE, "Map.prototype.has");

  const TNode<OrderedHashMap> table =
      CAST(LoadObjectField(CAST(receiver), JSMap::kTableOffset));

  Label if_found(this), if_not_found(this);
  Branch(TableHasKey(context, table, key), &if_found, &if_not_found);

  BIND(&if_found);
  Return(TrueConstant());

  BIND(&if_not_found);
  Return(FalseConstant());
}

TNode<BoolT> CollectionsBuiltinsAssembler::TableHasKey(
    const TNode<Object> context, TNode<OrderedHashMap> table,
    TNode<Object> key) {
  TNode<Smi> index =
      CAST(CallBuiltin(Builtin::kFindOrderedHashMapEntry, context, table, key));

  return SmiGreaterThanOrEqual(index, SmiConstant(0));
}

const TNode<Object> CollectionsBuiltinsAssembler::NormalizeNumberKey(
    const TNode<Object> key) {
  TVARIABLE(Object, result, key);
  Label done(this);

  GotoIf(TaggedIsSmi(key), &done);
  GotoIfNot(IsHeapNumber(CAST(key)), &done);
  const TNode<Float64T> number = LoadHeapNumberValue(CAST(key));
  GotoIfNot(Float64Equal(number, Float64Constant(0.0)), &done);
  // We know the value is zero, so we take the key to be Smi 0.
  // Another option would be to normalize to Smi here.
  result = SmiConstant(0);
  Goto(&done);

  BIND(&done);
  return result.value();
}

template <typename CollectionType>
TNode<CollectionType> CollectionsBuiltinsAssembler::AddToOrderedHashTable(
    const TNode<CollectionType> table, const TNode<Object> key,
    const GrowCollection<CollectionType>& grow,
    const StoreAtEntry<CollectionType>& store_at_new_entry,
    const StoreAtEntry<CollectionType>& store_at_existing_entry) {
  TVARIABLE(CollectionType, table_var, table);
  TVARIABLE(IntPtrT, entry_start_position_or_hash, IntPtrConstant(0));
  Label entry_found(this), not_found(this), done(this);

  TryLookupOrderedHashTableIndex<CollectionType>(
      table, key, &entry_start_position_or_hash, &entry_found, &not_found);

  BIND(&entry_found);
  {
    // If we found the entry, we just store the value there.
    store_at_existing_entry(table, entry_start_position_or_hash.value());
    Goto(&done);
  }

  Label no_hash(this), add_entry(this), store_new_entry(this);
  BIND(&not_found);
  {
    // If we have a hash code, we can start adding the new entry.
    GotoIf(IntPtrGreaterThan(entry_start_position_or_hash.value(),
                             IntPtrConstant(0)),
           &add_entry);

    // Otherwise, g
"""


```