Response:
Let's break down the thought process for analyzing this C++ header file for V8 builtins.

**1. Initial Scan and Identification:**

* **Filename:** `builtins-collections-gen.h` suggests this file is related to the built-in collection objects in JavaScript (like Map, Set, WeakMap, WeakSet). The `.h` extension confirms it's a header file, likely containing declarations.
* **Copyright & License:** Standard boilerplate, indicating ownership and usage terms.
* **Includes:** `#include "src/codegen/code-stub-assembler.h"` is a key clue. `CodeStubAssembler` is a V8 class used for generating low-level code (often assembly). This tells us the file is involved in the implementation of collection functionalities at a relatively low level.
* **Namespaces:** `namespace v8 { namespace internal { ... } }` standard V8 organization.

**2. Core Functionality Identification (Based on Class Names and Function Signatures):**

* **`BranchIfIterableWithOriginalKeyOrValueMapIterator` & `BranchIfIterableWithOriginalValueSetIterator`:** These functions clearly check if an object is a specific type of iterator (Map/Set key/value iterators) and if it still has its *original* behavior. This immediately links to JavaScript iterator functionality.
* **`BaseCollectionsAssembler`:** This base class is the heart of the file. The inheritance from `CodeStubAssembler` reinforces the low-level code generation aspect. The presence of the `Variant` enum (`kMap`, `kSet`, `kWeakMap`, `kWeakSet`) confirms its role in handling different collection types.
* **Methods within `BaseCollectionsAssembler`:**  A systematic review of the methods provides a good understanding:
    * **`AddConstructorEntry` / `AddConstructorEntries` / `AddConstructorEntriesFrom*`:** These are clearly involved in the construction of collection objects, taking initial entries as input. The variations (from fast arrays, iterables, existing collections) indicate optimization strategies.
    * **`AllocateJSCollection` / `AllocateTable`:**  Allocation of the underlying memory structures for collections.
    * **`GenerateConstructor`:**  The entry point for creating collection instances.
    * **`GetAddFunction` / `GetConstructor` / `GetInitialAddFunction`:** Accessing the built-in methods and constructors of collections. The "Initial" variants suggest optimization for cases where prototypes haven't been modified.
    * **`GotoIfInitialAddFunctionModified` / `HasInitialCollectionPrototype`:** Checks for modifications to prototypes, important for performance optimizations.
    * **`LoadAndNormalizeFixedArrayElement` / `LoadAndNormalizeFixedDoubleArrayElement`:**  Loading elements from internal V8 array structures.
* **`CollectionsBuiltinsAssembler`:** Inherits from `BaseCollectionsAssembler`, suggesting it provides more specific implementations or utilities for collection builtins. The methods here deal with:
    * **Table operations:** `AddToSetTable`, `TableHasKey`, `DeleteFromSetTable`.
    * **Iteration:** `NextKeyIndexPair*`, `NextKeyValueIndexTuple*`.
    * **Grouping:** `AddValueToKeyedGroup`.
    * **Normalization:** `NormalizeNumberKey`.
    * **Low-level memory access:** `UnsafeStoreValueInOrderedHashMapEntry`.
    * **Iterator handling:** `MapIteratorToList`, `SetOrSetIteratorToList`.
    * **Hashing:** `GetHash`, `CallGetHashRaw`, `CallGetOrCreateHashRaw`, `ComputeStringHash`.
    * **Entry lookup:** `FindOrderedHashTableEntryFor*Key`, `TryLookupOrderedHashTableIndex`.
    * **Ordered hash table manipulation:** `AddToOrderedHashTable`, `StoreOrderedHashTableNewEntry`, `Store*InOrderedHashMapEntry`, `Load*FromOrderedHashMapEntry`.
* **`WeakCollectionsBuiltinsAssembler`:** Focuses on WeakMap and WeakSet, dealing with:
    * **Ephemeron hash tables:** The core data structure for weak collections.
    * **Key hashing and comparison:** `GetHash`, `CreateIdentityHash`, `FindKeyIndex*`.
    * **Table management:** `AllocateTable`, `InsufficientCapacityToAdd`, `ShouldRehash`, `ShouldShrink`.
    * **Entry manipulation:** `AddEntry`, `RemoveEntry`.

**3. Connecting to JavaScript Functionality:**

* The names of the classes and many functions directly correspond to JavaScript collection objects and their methods (Map, Set, WeakMap, WeakSet, `add`, `set`, iterators, etc.).
* The iterator checking functions directly relate to the behavior of `Map.prototype.keys()`, `Map.prototype.values()`, `Set.prototype.values()`, etc.
* The constructor-related functions are used when creating new `Map`, `Set`, `WeakMap`, and `WeakSet` instances.

**4. Identifying Potential Torque Usage:**

* The comment "Methods after this point should really be protected but are exposed for Torque." in `CollectionsBuiltinsAssembler` is a strong indicator. Torque is V8's domain-specific language for writing builtins. The `.tq` file extension mentioned in the prompt would be the definitive sign.

**5. Considering User Errors and Code Logic:**

* **User Errors:**  Modifying the prototypes of built-in collections is a classic mistake. The checks for prototype modifications in the code (`GotoIfInitialAddFunctionModified`, `HasInitialCollectionPrototype`) highlight the importance of not doing this for performance reasons.
* **Code Logic:** The various `AddConstructorEntriesFrom*` functions demonstrate different strategies for initializing collections, optimizing for cases like direct array input or existing collections. The hashing and collision resolution logic in the `OrderedHashTable` functions is also a significant area of code logic.

**6. Structuring the Answer:**

Finally, the information is organized into the requested categories:

* **Functionality:** A high-level summary of the file's purpose.
* **Torque:** Explicitly addressing the `.tq` extension.
* **JavaScript Examples:** Providing clear examples of how the C++ code relates to JavaScript usage.
* **Code Logic Reasoning:** Focusing on the constructor logic as a key example.
* **Common Programming Errors:**  Highlighting prototype modification as a common mistake.

**Self-Correction/Refinement during the thought process:**

* Initially, I might just see `CodeStubAssembler` and think "assembly generation."  However, looking at the specific function names related to collections refines this to "low-level *implementation* of collection builtins."
*  Seeing multiple `AddConstructorEntriesFrom...` functions prompts the question: "Why so many?" leading to the understanding of optimization strategies.
*  The "Unsafe" prefixed functions indicate direct memory manipulation and the potential for errors if used incorrectly, further reinforcing the low-level nature.
*  The mention of "protectors" hints at V8's optimization techniques and the conditions under which certain optimizations can be applied.

By following these steps, combining code analysis with knowledge of V8 architecture and JavaScript behavior, we can arrive at a comprehensive understanding of the provided header file.
好的，让我们来分析一下 `v8/src/builtins/builtins-collections-gen.h` 这个 V8 源代码文件。

**文件功能概述:**

`v8/src/builtins/builtins-collections-gen.h` 是 V8 JavaScript 引擎中关于集合类型（Collections，如 Map、Set、WeakMap、WeakSet）内置函数的代码生成器头文件。 它定义了一些辅助函数和类，用于在 V8 的 Torque 语言（一种用于编写高效内置函数的 DSL）中生成和管理这些集合类型的内置函数代码。

**具体功能点:**

1. **提供构建集合的通用框架:** 文件中定义了 `BaseCollectionsAssembler` 基类，它继承自 `CodeStubAssembler`，这是一个用于生成低级代码的 V8 类。 `BaseCollectionsAssembler` 提供了构建各种集合类型（通过 `Variant` 枚举区分）的通用方法，例如：
    *  添加构造函数条目 (`AddConstructorEntry`, `AddConstructorEntries`, `AddConstructorEntriesFrom*`)
    *  分配集合实例和底层存储 (`AllocateJSCollection`, `AllocateTable`)
    *  获取添加元素的函数 (`GetAddFunction`)
    *  检查原型是否被修改 (`GotoIfInitialAddFunctionModified`, `HasInitialCollectionPrototype`)
    *  生成构造函数 (`GenerateConstructor`)

2. **处理不同类型的集合:** 通过 `Variant` 枚举 (`kMap`, `kSet`, `kWeakMap`, `kWeakSet`)，该文件中的代码可以针对不同类型的集合生成特定的代码逻辑。

3. **优化集合的构造:** 文件中包含了针对不同初始化方式的优化路径，例如：
    *  从快速 JS 数组初始化 (`AddConstructorEntriesFromFastJSArray`)
    *  从可迭代对象初始化 (`AddConstructorEntriesFromIterable`)
    *  从现有的快速集合初始化 (`AddConstructorEntriesFromFastCollection`)

4. **处理迭代器:**  提供了检查对象是否是具有原始行为的 Map 或 Set 迭代器的函数 (`BranchIfIterableWithOriginalKeyOrValueMapIterator`, `BranchIfIterableWithOriginalValueSetIterator`)。这对于优化某些迭代操作非常重要。

5. **提供操作有序哈希表的工具:** `CollectionsBuiltinsAssembler` 类提供了操作有序哈希表的函数，这是 Map 和 Set 等集合类型的底层实现：
    *  添加、删除和查找键 (`AddToSetTable`, `TableHasKey`, `DeleteFromSetTable`)
    *  遍历哈希表 (`NextKeyIndexPair*`, `NextKeyValueIndexTuple*`)
    *  存储和加载键值对 (`StoreValueInOrderedHashMapEntry`, `LoadValueFromOrderedHashMapEntry`)

6. **处理弱集合的特殊逻辑:** `WeakCollectionsBuiltinsAssembler` 类专门处理 WeakMap 和 WeakSet，它们使用 EphemeronHashTable 作为底层存储，具有垃圾回收相关的特殊语义。

**关于 .tq 结尾:**

正如你所说，如果 `v8/src/builtins/builtins-collections-gen.h` 以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码文件**。 Torque 是一种 V8 专门设计的领域特定语言，用于编写高效的内置函数。 Torque 代码会被编译成 C++ 代码，然后被 V8 引擎使用。

**与 JavaScript 功能的关系及示例:**

这个头文件中的代码直接关系到 JavaScript 中 `Map`、`Set`、`WeakMap` 和 `WeakSet` 的行为。  当你在 JavaScript 中使用这些集合类型时，V8 引擎会执行由 Torque (最终编译成 C++) 实现的内置函数。

**JavaScript 示例:**

```javascript
// 创建一个 Map 实例
const myMap = new Map();
myMap.set('a', 1);
myMap.set('b', 2);

// 创建一个 Set 实例
const mySet = new Set();
mySet.add(1);
mySet.add(2);

// 创建一个 WeakMap 实例
const weakMap = new WeakMap();
const keyObj = {};
weakMap.set(keyObj, 'some info');

// 创建一个 WeakSet 实例
const weakSet = new WeakSet();
const anotherObj = {};
weakSet.add(anotherObj);
```

当你执行上述 JavaScript 代码时，V8 引擎会调用由 `builtins-collections-gen.h` (或其 `.tq` 版本编译后的 C++ 代码) 中定义的逻辑来实现 `Map`、`Set`、`WeakMap` 和 `WeakSet` 的构造、添加元素等操作。

例如，`AddConstructorEntries` 函数会被用于处理 `new Map([['a', 1], ['b', 2]])` 这样的构造方式，它会遍历传入的数组并将键值对添加到新的 Map 实例中。

**代码逻辑推理及假设输入与输出:**

假设我们正在处理 `Set` 的构造函数，并且输入是一个 JavaScript 数组 `[1, 2, 2, 3]`。

**假设输入:**

* `variant`: `kSet`
* `context`: 当前的 V8 上下文
* `native_context`: 原生 V8 上下文
* `collection`: 新创建的空的 `Set` 实例
* `initial_entries`: JavaScript 数组 `[1, 2, 2, 3]`

**涉及的 (简化的) 代码逻辑推理:**

1. `AddConstructorEntries` 函数会被调用。
2. 由于 `initial_entries` 是一个数组，`AddConstructorEntriesFromFastJSArray` 可能会被调用进行优化。
3. `AddConstructorEntriesFromFastJSArray` 会遍历输入数组。
4. 对于每个元素，它会调用 `GetAddFunction` 获取 `Set.prototype.add` 函数。
5. 然后，调用 `AddConstructorEntry`，该函数会调用 `Set.prototype.add` 来将元素添加到 `Set` 中。
6. 由于 `Set` 不允许重复元素，当处理到第二个 `2` 时，`Set.prototype.add` 会检查元素是否已存在，如果存在则不会添加。

**预期输出 (添加到 Set 中的元素):**

`1`, `2`, `3` (重复的 `2` 不会被添加)

**用户常见的编程错误及示例:**

1. **误解 WeakMap/WeakSet 的弱引用特性:** 用户可能会认为在 WeakMap 或 WeakSet 中存储对象后，即使没有其他地方引用该对象，它也会一直存在。实际上，一旦 WeakMap 或 WeakSet 中的键（对于 WeakMap）或值（对于 WeakSet）所引用的对象只被这些弱集合引用时，垃圾回收器就可能回收这些对象，导致在 WeakMap/WeakSet 中找不到对应的条目。

   ```javascript
   let key = {};
   const weakMap = new WeakMap();
   weakMap.set(key, 'data');

   key = null; // key 对象不再被强引用

   // 在某个时候，垃圾回收器可能会回收原来的 {} 对象
   // 之后尝试从 weakMap 中获取数据可能会返回 undefined
   console.log(weakMap.get({})); // 可能会返回 undefined，因为 {} !== 原来的 key
   ```

2. **修改集合的原型对象:** 虽然 JavaScript 允许修改内置对象的原型，但这通常是不推荐的做法，因为它可能导致意外的行为和性能问题。 V8 的代码中包含检查原型是否被修改的逻辑，这表明引擎在某些情况下会针对未修改原型的标准集合进行优化。

   ```javascript
   // 不推荐这样做
   Map.prototype.customMethod = function() {
       console.log('Custom method');
   };

   const myMap = new Map();
   myMap.customMethod();
   ```

   修改原型可能会使 V8 无法应用某些优化，因为引擎需要处理原型链上可能存在的自定义行为。

总而言之，`v8/src/builtins/builtins-collections-gen.h` 是 V8 引擎中实现 JavaScript 集合类型核心功能的关键文件，它通过提供通用的代码生成框架和针对不同集合类型的特定逻辑，确保了这些集合类型的高效运行。 如果它是 `.tq` 文件，则意味着它是用 V8 的 Torque 语言编写的。

### 提示词
```
这是目录为v8/src/builtins/builtins-collections-gen.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-collections-gen.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_BUILTINS_BUILTINS_COLLECTIONS_GEN_H_
#define V8_BUILTINS_BUILTINS_COLLECTIONS_GEN_H_

#include "src/codegen/code-stub-assembler.h"

namespace v8 {
namespace internal {

void BranchIfIterableWithOriginalKeyOrValueMapIterator(
    compiler::CodeAssemblerState* state, TNode<Object> iterable,
    TNode<Context> context, compiler::CodeAssemblerLabel* if_true,
    compiler::CodeAssemblerLabel* if_false);

void BranchIfIterableWithOriginalValueSetIterator(
    compiler::CodeAssemblerState* state, TNode<Object> iterable,
    TNode<Context> context, compiler::CodeAssemblerLabel* if_true,
    compiler::CodeAssemblerLabel* if_false);

class BaseCollectionsAssembler : public CodeStubAssembler {
 public:
  explicit BaseCollectionsAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  virtual ~BaseCollectionsAssembler() = default;

  void GotoIfCannotBeHeldWeakly(const TNode<Object> obj,
                                Label* if_cannot_be_held_weakly);

 protected:
  enum Variant { kMap, kSet, kWeakMap, kWeakSet };

  // Adds an entry to a collection.  For Maps, properly handles extracting the
  // key and value from the entry (see LoadKeyValue()).
  void AddConstructorEntry(Variant variant, TNode<Context> context,
                           TNode<Object> collection, TNode<Object> add_function,
                           TNode<Object> key_value,
                           Label* if_may_have_side_effects = nullptr,
                           Label* if_exception = nullptr,
                           TVariable<Object>* var_exception = nullptr);

  virtual void GetEntriesIfFastCollectionOrIterable(
      Variant variant, TNode<Object> initial_entries, TNode<Context> context,
      TVariable<HeapObject>* var_entries_table,
      TVariable<IntPtrT>* var_number_of_elements,
      Label* if_not_fast_collection) = 0;

  // Adds constructor entries to a collection.  Choosing a fast path when
  // possible.
  void AddConstructorEntries(Variant variant, TNode<Context> context,
                             TNode<NativeContext> native_context,
                             TNode<HeapObject> collection,
                             TNode<Object> initial_entries);

  // Fast path for adding constructor entries.  Assumes the entries are a fast
  // JS array (see CodeStubAssembler::BranchIfFastJSArray()).
  void AddConstructorEntriesFromFastJSArray(
      Variant variant, TNode<Context> context, TNode<Context> native_context,
      TNode<Object> collection, TNode<JSArray> fast_jsarray,
      Label* if_may_have_side_effects, TVariable<IntPtrT>& var_current_index);

  // Adds constructor entries to a collection using the iterator protocol.
  void AddConstructorEntriesFromIterable(
      Variant variant, TNode<Context> context, TNode<Context> native_context,
      TNode<Object> collection, TNode<Object> iterable, Label* if_exception,
      TVariable<JSReceiver>* var_iterator, TVariable<Object>* var_exception);

  virtual void AddConstructorEntriesFromFastCollection(
      Variant variant, TNode<HeapObject> collection,
      TNode<HeapObject> source_table) = 0;

  // Constructs a collection instance. Choosing a fast path when possible.
  TNode<JSObject> AllocateJSCollection(TNode<Context> context,
                                       TNode<JSFunction> constructor,
                                       TNode<JSReceiver> new_target);

  // Fast path for constructing a collection instance if the constructor
  // function has not been modified.
  TNode<JSObject> AllocateJSCollectionFast(TNode<JSFunction> constructor);

  // Fallback for constructing a collection instance if the constructor function
  // has been modified.
  TNode<JSObject> AllocateJSCollectionSlow(TNode<Context> context,
                                           TNode<JSFunction> constructor,
                                           TNode<JSReceiver> new_target);

  // Allocates the backing store for a collection.
  virtual TNode<HeapObject> AllocateTable(
      Variant variant, TNode<IntPtrT> at_least_space_for) = 0;

  // Main entry point for a collection constructor builtin.
  void GenerateConstructor(Variant variant,
                           Handle<String> constructor_function_name,
                           TNode<Object> new_target, TNode<IntPtrT> argc,
                           TNode<Context> context);

  // Retrieves the collection function that adds an entry. `set` for Maps and
  // `add` for Sets.
  TNode<Object> GetAddFunction(Variant variant, TNode<Context> context,
                               TNode<Object> collection);

  // Retrieves the collection constructor function.
  TNode<JSFunction> GetConstructor(Variant variant,
                                   TNode<Context> native_context);

  // Retrieves the initial collection function that adds an entry. Should only
  // be called when it is certain that a collection prototype's map hasn't been
  // changed.
  TNode<JSFunction> GetInitialAddFunction(Variant variant,
                                          TNode<Context> native_context);

  // Checks whether {collection}'s initial add/set function has been modified
  // (depending on {variant}, loaded from {native_context}).
  void GotoIfInitialAddFunctionModified(Variant variant,
                                        TNode<NativeContext> native_context,
                                        TNode<HeapObject> collection,
                                        Label* if_modified);

  // Gets root index for the name of the add/set function.
  RootIndex GetAddFunctionNameIndex(Variant variant);

  // Retrieves the offset to access the backing table from the collection.
  int GetTableOffset(Variant variant);

  // Determines whether the collection's prototype has been modified.
  TNode<BoolT> HasInitialCollectionPrototype(Variant variant,
                                             TNode<Context> native_context,
                                             TNode<Object> collection);

  // Gets the initial prototype map for given collection {variant}.
  TNode<Map> GetInitialCollectionPrototype(Variant variant,
                                           TNode<Context> native_context);

  // Loads an element from a fixed array.  If the element is the hole, returns
  // `undefined`.
  TNode<Object> LoadAndNormalizeFixedArrayElement(TNode<FixedArray> elements,
                                                  TNode<IntPtrT> index);

  // Loads an element from a fixed double array.  If the element is the hole,
  // returns `undefined`.
  TNode<Object> LoadAndNormalizeFixedDoubleArrayElement(
      TNode<HeapObject> elements, TNode<IntPtrT> index);
};

class CollectionsBuiltinsAssembler : public BaseCollectionsAssembler {
 public:
  explicit CollectionsBuiltinsAssembler(compiler::CodeAssemblerState* state)
      : BaseCollectionsAssembler(state) {}

  // Check whether |iterable| is a JS_MAP_KEY_ITERATOR_TYPE or
  // JS_MAP_VALUE_ITERATOR_TYPE object that is not partially consumed and still
  // has original iteration behavior.
  void BranchIfIterableWithOriginalKeyOrValueMapIterator(TNode<Object> iterable,
                                                         TNode<Context> context,
                                                         Label* if_true,
                                                         Label* if_false);

  // Check whether |iterable| is a JS_SET_TYPE or JS_SET_VALUE_ITERATOR_TYPE
  // object that still has original iteration behavior. In case of the iterator,
  // the iterator also must not have been partially consumed.
  void BranchIfIterableWithOriginalValueSetIterator(TNode<Object> iterable,
                                                    TNode<Context> context,
                                                    Label* if_true,
                                                    Label* if_false);

  // Adds an element to a set if the element is not already in the set.
  TNode<OrderedHashSet> AddToSetTable(TNode<Object> context,
                                      TNode<OrderedHashSet> table,
                                      TNode<Object> key,
                                      TNode<String> method_name);
  // Direct iteration helpers.
  template <typename CollectionType>
  TorqueStructKeyIndexPair NextKeyIndexPairUnmodifiedTable(
      const TNode<CollectionType> table, const TNode<Int32T> number_of_buckets,
      const TNode<Int32T> used_capacity, const TNode<IntPtrT> index,
      Label* if_end);

  template <typename CollectionType>
  TorqueStructKeyIndexPair NextKeyIndexPair(const TNode<CollectionType> table,
                                            const TNode<IntPtrT> index,
                                            Label* if_end);

  TorqueStructKeyValueIndexTuple NextKeyValueIndexTupleUnmodifiedTable(
      const TNode<OrderedHashMap> table, const TNode<Int32T> number_of_buckets,
      const TNode<Int32T> used_capacity, const TNode<IntPtrT> index,
      Label* if_end);

  TorqueStructKeyValueIndexTuple NextKeyValueIndexTuple(
      const TNode<OrderedHashMap> table, const TNode<IntPtrT> index,
      Label* if_end);

  // Checks if the set/map contains a key.
  TNode<BoolT> TableHasKey(const TNode<Object> context,
                           TNode<OrderedHashSet> table, TNode<Object> key);
  TNode<BoolT> TableHasKey(const TNode<Object> context,
                           TNode<OrderedHashMap> table, TNode<Object> key);

  // Adds {value} to a FixedArray keyed by {key} in {groups}.
  //
  // Utility used by Object.groupBy and Map.groupBy.
  const TNode<OrderedHashMap> AddValueToKeyedGroup(
      const TNode<OrderedHashMap> groups, const TNode<Object> key,
      const TNode<Object> value, const TNode<String> methodName);

  // Normalizes -0 to +0.
  const TNode<Object> NormalizeNumberKey(const TNode<Object> key);

  // Methods after this point should really be protected but are exposed for
  // Torque.
  void UnsafeStoreValueInOrderedHashMapEntry(const TNode<OrderedHashMap> table,
                                             const TNode<Object> value,
                                             const TNode<IntPtrT> entry) {
    return StoreValueInOrderedHashMapEntry(table, value, entry,
                                           CheckBounds::kDebugOnly);
  }

  TNode<Smi> DeleteFromSetTable(const TNode<Object> context,
                                TNode<OrderedHashSet> table, TNode<Object> key,
                                Label* not_found);

  TorqueStructOrderedHashSetIndexPair TransitionOrderedHashSetNoUpdate(
      const TNode<OrderedHashSet> table, const TNode<IntPtrT> index);

 protected:
  template <typename IteratorType>
  TNode<HeapObject> AllocateJSCollectionIterator(
      const TNode<Context> context, int map_index,
      const TNode<HeapObject> collection);
  TNode<HeapObject> AllocateTable(Variant variant,
                                  TNode<IntPtrT> at_least_space_for) override;
  TNode<Uint32T> GetHash(const TNode<HeapObject> key);
  TNode<Uint32T> CallGetHashRaw(const TNode<HeapObject> key);
  TNode<Smi> CallGetOrCreateHashRaw(const TNode<HeapObject> key);

  // Transitions the iterator to the non obsolete backing store.
  // This is a NOP if the [table] is not obsolete.
  template <typename TableType>
  using UpdateInTransition = std::function<void(const TNode<TableType> table,
                                                const TNode<IntPtrT> index)>;
  template <typename TableType>
  std::pair<TNode<TableType>, TNode<IntPtrT>> Transition(
      const TNode<TableType> table, const TNode<IntPtrT> index,
      UpdateInTransition<TableType> const& update_in_transition);
  template <typename IteratorType, typename TableType>
  std::pair<TNode<TableType>, TNode<IntPtrT>> TransitionAndUpdate(
      const TNode<IteratorType> iterator);

  template <typename TableType>
  std::tuple<TNode<Object>, TNode<IntPtrT>, TNode<IntPtrT>>
  NextSkipHashTableHoles(TNode<TableType> table, TNode<IntPtrT> index,
                         Label* if_end);
  template <typename TableType>
  std::tuple<TNode<Object>, TNode<IntPtrT>, TNode<IntPtrT>>
  NextSkipHashTableHoles(TNode<TableType> table,
                         TNode<Int32T> number_of_buckets,
                         TNode<Int32T> used_capacity, TNode<IntPtrT> index,
                         Label* if_end);

  // A helper function to help extract the {table} from either a Set or
  // SetIterator. The function has a side effect of marking the
  // SetIterator (if SetIterator is passed) as exhausted.
  TNode<OrderedHashSet> SetOrSetIteratorToSet(TNode<Object> iterator);

  // Adds constructor entries to a collection when constructing from a Set
  void AddConstructorEntriesFromSet(TNode<JSSet> collection,
                                    TNode<OrderedHashSet> table);

  // a helper function to unwrap a fast js collection and load its length.
  // var_entries_table is a variable meant to store the unwrapped collection.
  // var_number_of_elements is a variable meant to store the length of the
  // unwrapped collection. the function jumps to if_not_fast_collection if the
  // collection is not a fast js collection.
  void GetEntriesIfFastCollectionOrIterable(
      Variant variant, TNode<Object> initial_entries, TNode<Context> context,
      TVariable<HeapObject>* var_entries_table,
      TVariable<IntPtrT>* var_number_of_elements,
      Label* if_not_fast_collection) override;

  // a helper to load constructor entries from a fast js collection.
  void AddConstructorEntriesFromFastCollection(
      Variant variant, TNode<HeapObject> collection,
      TNode<HeapObject> source_table) override;

  // Specialization for Smi.
  // The {result} variable will contain the entry index if the key was found,
  // or the hash code otherwise.
  template <typename CollectionType>
  void FindOrderedHashTableEntryForSmiKey(TNode<CollectionType> table,
                                          TNode<Smi> key_tagged,
                                          TVariable<IntPtrT>* result,
                                          Label* entry_found, Label* not_found);
  void SameValueZeroSmi(TNode<Smi> key_smi, TNode<Object> candidate_key,
                        Label* if_same, Label* if_not_same);

  // Specialization for heap numbers.
  // The {result} variable will contain the entry index if the key was found,
  // or the hash code otherwise.
  void SameValueZeroHeapNumber(TNode<Float64T> key_float,
                               TNode<Object> candidate_key, Label* if_same,
                               Label* if_not_same);
  template <typename CollectionType>
  void FindOrderedHashTableEntryForHeapNumberKey(
      TNode<CollectionType> table, TNode<HeapNumber> key_heap_number,
      TVariable<IntPtrT>* result, Label* entry_found, Label* not_found);

  // Specialization for bigints.
  // The {result} variable will contain the entry index if the key was found,
  // or the hash code otherwise.
  void SameValueZeroBigInt(TNode<BigInt> key, TNode<Object> candidate_key,
                           Label* if_same, Label* if_not_same);
  template <typename CollectionType>
  void FindOrderedHashTableEntryForBigIntKey(TNode<CollectionType> table,
                                             TNode<BigInt> key_big_int,
                                             TVariable<IntPtrT>* result,
                                             Label* entry_found,
                                             Label* not_found);

  // Specialization for string.
  // The {result} variable will contain the entry index if the key was found,
  // or the hash code otherwise.
  template <typename CollectionType>
  void FindOrderedHashTableEntryForStringKey(TNode<CollectionType> table,
                                             TNode<String> key_tagged,
                                             TVariable<IntPtrT>* result,
                                             Label* entry_found,
                                             Label* not_found);
  TNode<Uint32T> ComputeStringHash(TNode<String> string_key);
  void SameValueZeroString(TNode<String> key_string,
                           TNode<Object> candidate_key, Label* if_same,
                           Label* if_not_same);

  // Specialization for non-strings, non-numbers. For those we only need
  // reference equality to compare the keys.
  // The {result} variable will contain the entry index if the key was found,
  // or the hash code otherwise. If the hash-code has not been computed, it
  // should be Smi -1.
  template <typename CollectionType>
  void FindOrderedHashTableEntryForOtherKey(TNode<CollectionType> table,
                                            TNode<HeapObject> key_heap_object,
                                            TVariable<IntPtrT>* result,
                                            Label* entry_found,
                                            Label* not_found);

  // Generates code to add an entry keyed by {key} to an instance of
  // OrderedHashTable subclass {table}.
  //
  // Takes 3 functions:
  //   - {grow} generates code to return a OrderedHashTable subclass instance
  //     with space to store the entry.
  //   - {store_new_entry} generates code to store into a new entry, for the
  //     case when {table} didn't already have an entry keyed by {key}.
  //   - {store_existing_entry} generates code to store into an existing entry,
  //     for the case when {table} already has an entry keyed by {key}.
  //
  // Both {store_new_entry} and {store_existing_entry} take the table and an
  // offset to the entry as parameters.
  template <typename CollectionType>
  using GrowCollection = std::function<const TNode<CollectionType>()>;
  template <typename CollectionType>
  using StoreAtEntry = std::function<void(const TNode<CollectionType> table,
                                          const TNode<IntPtrT> entry_start)>;
  template <typename CollectionType>
  TNode<CollectionType> AddToOrderedHashTable(
      const TNode<CollectionType> table, const TNode<Object> key,
      const GrowCollection<CollectionType>& grow,
      const StoreAtEntry<CollectionType>& store_at_new_entry,
      const StoreAtEntry<CollectionType>& store_at_existing_entry);

  template <typename CollectionType>
  void TryLookupOrderedHashTableIndex(const TNode<CollectionType> table,
                                      const TNode<Object> key,
                                      TVariable<IntPtrT>* result,
                                      Label* if_entry_found,
                                      Label* if_not_found);

  // Helper function to store a new entry when constructing sets from sets.
  template <typename CollectionType>
  void AddNewToOrderedHashTable(
      const TNode<CollectionType> table, const TNode<Object> normalised_key,
      const TNode<IntPtrT> number_of_buckets, const TNode<IntPtrT> occupancy,
      const StoreAtEntry<CollectionType>& store_at_new_entry);

  void AddNewToOrderedHashSet(const TNode<OrderedHashSet> table,
                              const TNode<Object> key,
                              const TNode<IntPtrT> number_of_buckets,
                              const TNode<IntPtrT> occupancy) {
    TNode<Object> normalised_key = NormalizeNumberKey(key);
    StoreAtEntry<OrderedHashSet> store_at_new_entry =
        [this, normalised_key](const TNode<OrderedHashSet> table,
                               const TNode<IntPtrT> entry_start) {
          UnsafeStoreKeyInOrderedHashSetEntry(table, normalised_key,
                                              entry_start);
        };
    AddNewToOrderedHashTable<OrderedHashSet>(table, normalised_key,
                                             number_of_buckets, occupancy,
                                             store_at_new_entry);
  }

  // Generates code to store a new entry into {table}, connecting to the bucket
  // chain, and updating the bucket head. {store_new_entry} is called to
  // generate the code to store the payload (e.g., the key and value for
  // OrderedHashMap).
  template <typename CollectionType>
  void StoreOrderedHashTableNewEntry(
      const TNode<CollectionType> table, const TNode<IntPtrT> hash,
      const TNode<IntPtrT> number_of_buckets, const TNode<IntPtrT> occupancy,
      const StoreAtEntry<CollectionType>& store_at_new_entry);

  // Store payload (key, value, or both) in {table} at {entry}. Does not connect
  // the bucket chain and update the bucket head.
  void StoreValueInOrderedHashMapEntry(
      const TNode<OrderedHashMap> table, const TNode<Object> value,
      const TNode<IntPtrT> entry,
      CheckBounds check_bounds = CheckBounds::kAlways);
  void StoreKeyValueInOrderedHashMapEntry(
      const TNode<OrderedHashMap> table, const TNode<Object> key,
      const TNode<Object> value, const TNode<IntPtrT> entry,
      CheckBounds check_bounds = CheckBounds::kAlways);
  void StoreKeyInOrderedHashSetEntry(
      const TNode<OrderedHashSet> table, const TNode<Object> key,
      const TNode<IntPtrT> entry,
      CheckBounds check_bounds = CheckBounds::kAlways);

  void UnsafeStoreKeyValueInOrderedHashMapEntry(
      const TNode<OrderedHashMap> table, const TNode<Object> key,
      const TNode<Object> value, const TNode<IntPtrT> entry) {
    return StoreKeyValueInOrderedHashMapEntry(table, key, value, entry,
                                              CheckBounds::kDebugOnly);
  }
  void UnsafeStoreKeyInOrderedHashSetEntry(const TNode<OrderedHashSet> table,
                                           const TNode<Object> key,
                                           const TNode<IntPtrT> entry) {
    return StoreKeyInOrderedHashSetEntry(table, key, entry,
                                         CheckBounds::kDebugOnly);
  }

  TNode<Object> LoadValueFromOrderedHashMapEntry(
      const TNode<OrderedHashMap> table, const TNode<IntPtrT> entry,
      CheckBounds check_bounds = CheckBounds::kAlways);

  TNode<Object> UnsafeLoadValueFromOrderedHashMapEntry(
      const TNode<OrderedHashMap> table, const TNode<IntPtrT> entry) {
    return LoadValueFromOrderedHashMapEntry(table, entry,
                                            CheckBounds::kDebugOnly);
  }

  // Load payload (key or value) from {table} at {entry}.
  template <typename CollectionType>
  TNode<Object> LoadKeyFromOrderedHashTableEntry(
      const TNode<CollectionType> table, const TNode<IntPtrT> entry,
      CheckBounds check_bounds = CheckBounds::kAlways);

  template <typename CollectionType>
  TNode<Object> UnsafeLoadKeyFromOrderedHashTableEntry(
      const TNode<CollectionType> table, const TNode<IntPtrT> entry) {
    return LoadKeyFromOrderedHashTableEntry(table, entry,
                                            CheckBounds::kDebugOnly);
  }

  // Create a JSArray with PACKED_ELEMENTS kind from a Map.prototype.keys() or
  // Map.prototype.values() iterator. The iterator is assumed to satisfy
  // IterableWithOriginalKeyOrValueMapIterator. This function will skip the
  // iterator and iterate directly on the underlying hash table. In the end it
  // will update the state of the iterator to 'exhausted'.
  TNode<JSArray> MapIteratorToList(TNode<Context> context,
                                   TNode<JSMapIterator> iterator);

  // Create a JSArray with PACKED_ELEMENTS kind from a Set.prototype.keys() or
  // Set.prototype.values() iterator, or a Set. The |iterable| is assumed to
  // satisfy IterableWithOriginalValueSetIterator. This function will skip the
  // iterator and iterate directly on the underlying hash table. In the end, if
  // |iterable| is an iterator, it will update the state of the iterator to
  // 'exhausted'.
  TNode<JSArray> SetOrSetIteratorToList(TNode<Context> context,
                                        TNode<HeapObject> iterable);

  void BranchIfMapIteratorProtectorValid(Label* if_true, Label* if_false);
  void BranchIfSetIteratorProtectorValid(Label* if_true, Label* if_false);

  // Builds code that finds OrderedHashTable entry for a key with hash code
  // {hash} with using the comparison code generated by {key_compare}. The code
  // jumps to {entry_found} if the key is found, or to {not_found} if the key
  // was not found. In the {entry_found} branch, the variable
  // entry_start_position will be bound to the index of the entry (relative to
  // OrderedHashTable::kHashTableStartIndex).
  //
  // The {CollectionType} template parameter stands for the particular instance
  // of OrderedHashTable, it should be OrderedHashMap or OrderedHashSet.
  template <typename CollectionType>
  void FindOrderedHashTableEntry(
      const TNode<CollectionType> table, const TNode<Uint32T> hash,
      const std::function<void(TNode<Object>, Label*, Label*)>& key_compare,
      TVariable<IntPtrT>* entry_start_position, Label* entry_found,
      Label* not_found);

  TNode<Word32T> ComputeUnseededHash(TNode<IntPtrT> key);
};

class WeakCollectionsBuiltinsAssembler : public BaseCollectionsAssembler {
 public:
  explicit WeakCollectionsBuiltinsAssembler(compiler::CodeAssemblerState* state)
      : BaseCollectionsAssembler(state) {}

 protected:
  void AddEntry(TNode<EphemeronHashTable> table, TNode<IntPtrT> key_index,
                TNode<Object> key, TNode<Object> value,
                TNode<Int32T> number_of_elements);

  TNode<HeapObject> AllocateTable(Variant variant,
                                  TNode<IntPtrT> at_least_space_for) override;

  TNode<IntPtrT> GetHash(const TNode<HeapObject> key, Label* if_no_hash);
  // Generates and sets the identity for a JSRececiver.
  TNode<Smi> CreateIdentityHash(TNode<Object> receiver);
  TNode<IntPtrT> EntryMask(TNode<IntPtrT> capacity);
  TNode<IntPtrT> Coefficient(TNode<IntPtrT> capacity);

  // Builds code that finds the EphemeronHashTable entry for a {key} using the
  // comparison code generated by {key_compare}. The key index is returned if
  // the {key} is found.
  using KeyComparator =
      std::function<void(TNode<Object> entry_key, Label* if_same)>;
  TNode<IntPtrT> FindKeyIndex(TNode<HeapObject> table, TNode<IntPtrT> key_hash,
                              TNode<IntPtrT> capacity,
                              const KeyComparator& key_compare);

  // Builds code that finds an EphemeronHashTable entry available for a new
  // entry.
  TNode<IntPtrT> FindKeyIndexForInsertion(TNode<HeapObject> table,
                                          TNode<IntPtrT> key_hash,
                                          TNode<IntPtrT> capacity);

  // Builds code that finds the EphemeronHashTable entry with key that matches
  // {key} and returns the entry's key index. If {key} cannot be found, jumps to
  // {if_not_found}.
  TNode<IntPtrT> FindKeyIndexForKey(TNode<HeapObject> table, TNode<Object> key,
                                    TNode<IntPtrT> hash,
                                    TNode<IntPtrT> capacity,
                                    Label* if_not_found);

  TNode<Word32T> InsufficientCapacityToAdd(TNode<Int32T> capacity,
                                           TNode<Int32T> number_of_elements,
                                           TNode<Int32T> number_of_deleted);
  TNode<IntPtrT> KeyIndexFromEntry(TNode<IntPtrT> entry);

  TNode<Int32T> LoadNumberOfElements(TNode<EphemeronHashTable> table,
                                     int offset);
  TNode<Int32T> LoadNumberOfDeleted(TNode<EphemeronHashTable> table,
                                    int offset = 0);
  TNode<EphemeronHashTable> LoadTable(TNode<JSWeakCollection> collection);
  TNode<IntPtrT> LoadTableCapacity(TNode<EphemeronHashTable> table);

  void RemoveEntry(TNode<EphemeronHashTable> table, TNode<IntPtrT> key_index,
                   TNode<IntPtrT> number_of_elements);
  TNode<BoolT> ShouldRehash(TNode<Int32T> number_of_elements,
                            TNode<Int32T> number_of_deleted);
  TNode<Word32T> ShouldShrink(TNode<IntPtrT> capacity,
                              TNode<IntPtrT> number_of_elements);
  TNode<IntPtrT> ValueIndexFromKeyIndex(TNode<IntPtrT> key_index);

  void GetEntriesIfFastCollectionOrIterable(
      Variant variant, TNode<Object> initial_entries, TNode<Context> context,
      TVariable<HeapObject>* var_entries_table,
      TVariable<IntPtrT>* var_number_of_elements,
      Label* if_not_fast_collection) override {
    UNREACHABLE();
  }

  void AddConstructorEntriesFromFastCollection(
      Variant variant, TNode<HeapObject> collection,
      TNode<HeapObject> source_table) override {
    UNREACHABLE();
  }
};

// Controls the key coercion behavior for Object.groupBy and Map.groupBy.
enum class GroupByCoercionMode { kZero, kProperty };

}  // namespace internal
}  // namespace v8

#endif  // V8_BUILTINS_BUILTINS_COLLECTIONS_GEN_H_
```