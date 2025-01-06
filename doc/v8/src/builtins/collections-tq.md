Response: Let's break down the thought process for analyzing this Torque code.

1. **Understand the Goal:** The request asks for a summary of the code's functionality, its relationship to JavaScript, examples, logic inference with inputs and outputs, and common programming errors it might prevent. The file name `collections.tq` and the namespace `collections` strongly suggest it's related to JavaScript's built-in collection types (Set, Map).

2. **Identify Key Structures:**  The code defines several key structures (`struct`) and macros. These are the building blocks. I'd start by listing them and noting their apparent purpose based on their names and contents:

    * `SetRecord`:  Likely represents an internal record for working with Set-like objects, containing the object itself, its size, and access to `has` and `keys` methods.
    * `KeyIndexPair`, `OrderedHashSetIndexPair`, `KeyValueIndexTuple`: These seem related to iterating over collections, holding keys, values, and internal indices. The names strongly suggest they are used with `OrderedHashSet` and `OrderedHashMap`.
    * `UnmodifiedOrderedHashSetIterator`, `OrderedHashSetIterator`, `UnmodifiedOrderedHashMapIterator`:  These are clearly iterators, with "Unmodified" versions implying they operate under the assumption that the underlying collection won't change during iteration.
    * `StableJSSetBackingTableWitness`, `StableJSMapBackingTableWitness`: These seem to be internal helpers to access and track the underlying storage of `Set` and `Map` instances, likely for optimization or consistency checks.

3. **Analyze Key Macros and Externs:** Next, examine the macros and `extern macro` declarations. These represent actions or operations.

    * `CloneFixedArray`: A low-level operation for copying arrays. Likely used in internal collection management.
    * `AddToSetTable`, `TableHasKey`, `DeleteFromSetTable`:  These are fundamental operations for manipulating the internal hash tables used by Sets. The presence of different `TableHasKey` versions hints at different underlying table types.
    * `OrderedHashSetShrink`:  An optimization to reduce the memory footprint of Sets.
    * `NextKeyIndexPairUnmodifiedTable`, `TransitionOrderedHashSetNoUpdate`, `NextKeyIndexPair`, `NextKeyValueIndexTupleUnmodifiedTable`, `NextKeyValueIndexTuple`: These are clearly related to the iteration process, likely handling advancing the internal pointers or indices within the hash tables. The "Unmodified" variants reinforce the idea of optimized iteration under certain conditions.
    * `LoadOrderedHashTableMetadata`:  Accesses internal properties of the hash tables (like number of buckets, elements, deleted elements).
    * `NewUnmodifiedOrderedHashSetIterator`, `NewOrderedHashSetIterator`, `NewUnmodifiedOrderedHashMapIterator`: Constructors for the iterator structures.
    * `UnsafeStoreValueInOrderedHashMapEntry`: A low-level, potentially performance-critical operation for writing values into a Map's storage. The "Unsafe" prefix suggests potential risks if used incorrectly.
    * `LoadKeyValuePairNoSideEffects`, `LoadKeyValuePair`: These macros seem to handle extracting key-value pairs, likely for iteration or other operations where pair representation is needed. The "NoSideEffects" version likely represents a fast path.
    * `GetSetRecord`:  A crucial macro for validating and extracting information from a Set-like object. It checks for the existence and callability of `size`, `has`, and `keys` properties.
    * `GetKeysIterator`:  A helper for getting an iterator specifically for the keys of a Set.
    * `CheckSetRecordHasJSSetMethods`, `CheckSetRecordHasJSMapMethods`: These macros appear to verify if the `keys` and `has` methods of a given object are the *standard* built-in methods of `Set` or `Map` respectively. This is likely an optimization to take faster code paths when dealing with native `Set` and `Map` instances.
    * `ShrinkOrderedHashSetIfNeeded`:  A higher-level macro that calls `OrderedHashSetShrink` based on the number of elements.
    * `NewStableBackingTableWitness` (both for Set and Map):  Creates the "witness" structures for tracking the underlying hash tables of `Set` and `Map`.

4. **Infer Functionality and Relationship to JavaScript:** Based on the names and the structures/macros, it becomes clear that this code deals with the *internal implementation* of JavaScript's `Set` and `Map` objects within the V8 engine. It provides mechanisms for:

    * Storing and retrieving elements (using hash tables).
    * Iterating over elements (with both potentially mutating and non-mutating iterators).
    * Managing the size and internal structure of these collections (shrinking, accessing metadata).
    * Validating objects to ensure they behave like `Set` or `Map`.

5. **Illustrate with JavaScript Examples:**  Connect the internal mechanisms to user-facing JavaScript behavior. For example:

    * `AddToSetTable` relates to `Set.prototype.add()`.
    * `TableHasKey` relates to `Set.prototype.has()` and `Map.prototype.has()`.
    * The iterator structures relate to the behavior of `for...of` loops and methods like `Set.prototype.keys()`, `Set.prototype.values()`, `Set.prototype.entries()`, and similarly for `Map`.
    * `GetSetRecord` is used internally when JavaScript code interacts with something *like* a Set, ensuring it has the necessary methods and properties.

6. **Develop Logic Inference Examples:** Choose a macro or function and illustrate its behavior with hypothetical inputs and outputs. `AddToSetTable` is a good example: "If the set `{1, 2}` is represented by `OrderedHashSet` `A`, and we call `AddToSetTable(A, 3, "3")`, the output would be a modified `OrderedHashSet` `A'` that represents `{1, 2, 3}`."  Focus on the *change* in the internal state.

7. **Identify Common Programming Errors:** Think about how the internal mechanisms prevent common JavaScript errors:

    * The `GetSetRecord` macro helps prevent errors when users pass non-object arguments to methods expecting Set-like objects.
    * The checks for callable `has` and `keys` methods prevent errors if these properties are accidentally overwritten with non-functions.
    * The distinction between modifying and non-modifying iterators highlights potential issues if a collection is modified during iteration in unexpected ways.

8. **Structure the Output:** Organize the findings into clear sections: Functionality, JavaScript Relationship, Logic Inference, and Common Errors. Use bullet points and code examples to make the information easy to understand.

9. **Refine and Elaborate:**  Review the summary and add more details where needed. For example, explaining *why* there are "Unmodified" iterators (performance optimization) or elaborating on the internal representation of `OrderedHashSet` and `OrderedHashMap` (though the code doesn't give full details on that).

By following this structured approach, you can effectively analyze and summarize complex source code like this Torque file. The key is to break it down into smaller, manageable parts and connect those parts to the broader context of JavaScript's behavior.
This Torque code defines internal mechanisms and data structures used by the V8 JavaScript engine to implement JavaScript's built-in `Set` and `Map` collections. It focuses on the underlying hash table implementations and iteration logic for these collections.

Here's a breakdown of its functionality:

**1. Definitions of Internal Data Structures:**

* **`SetRecord`:** Represents a record containing essential information about a Set-like object. This includes the object itself, its size, and references to its `has` and `keys` methods. This is used when dealing with objects that might behave like Sets but aren't necessarily native `Set` instances.

* **`KeyIndexPair` and `OrderedHashSetIndexPair`:**  Used for internal iteration over `OrderedHashSet`. `KeyIndexPair` holds a key and its index, while `OrderedHashSetIndexPair` holds the table and the current index.

* **`KeyValueIndexTuple`:** Similar to `KeyIndexPair`, but for `OrderedHashMap`, holding the key, the value, and the index.

* **`UnmodifiedOrderedHashSetIterator` and `OrderedHashSetIterator`:**  These structures define how to iterate over an `OrderedHashSet`. The "Unmodified" version assumes the underlying table won't change during iteration, allowing for optimizations. The regular version handles potential modifications.

* **`UnmodifiedOrderedHashMapIterator`:**  Defines how to iterate over an `OrderedHashMap` when the underlying table is not expected to change during iteration.

* **`StableJSSetBackingTableWitness` and `StableJSMapBackingTableWitness`:** These appear to be used for optimizations when dealing with stable (non-modified) native `Set` and `Map` instances. They provide a way to directly access the underlying hash table.

**2. Macros for Internal Operations:**

* **`CloneFixedArray`:**  A low-level macro for copying fixed-size arrays, likely used in the resizing or manipulation of the underlying hash tables.

* **Hash Table Manipulation (`AddToSetTable`, `TableHasKey`, `DeleteFromSetTable`, `OrderedHashSetShrink`):** These macros provide the core functionality for managing the internal hash tables used by `Set` and `Map`. They handle adding elements, checking for the existence of keys, deleting elements, and shrinking the table when it becomes too sparse.

* **Iteration Helpers (`NextKeyIndexPairUnmodifiedTable`, `NextKeyIndexPair`, `NextKeyValueIndexTupleUnmodifiedTable`, `NextKeyValueIndexTuple`):** These macros are used by the iterator structures to advance through the hash table and retrieve keys or key-value pairs. The "Unmodified" versions are optimized for cases where the table isn't changing.

* **Metadata Access (`LoadOrderedHashTableMetadata`):**  This macro retrieves metadata about the hash tables, such as the number of buckets, elements, and deleted elements.

* **Iterator Creation (`NewUnmodifiedOrderedHashSetIterator`, `NewOrderedHashSetIterator`, `NewUnmodifiedOrderedHashMapIterator`):** These macros create instances of the iterator structures.

* **Key-Value Pair Loading (`LoadKeyValuePairNoSideEffects`, `LoadKeyValuePair`):** These macros handle retrieving key-value pairs from various sources, including optimized fast arrays and general JavaScript objects. They ensure the retrieved value conforms to the expected key-value pair structure.

* **`GetSetRecord`:** This crucial macro takes a JavaScript object and attempts to extract the necessary information to treat it like a Set. It validates the presence and callability of `size`, `has`, and `keys` properties, throwing errors if the object doesn't conform.

* **`GetKeysIterator`:**  A helper macro to obtain an iterator for the keys of a Set-like object.

* **Method Checking (`CheckSetRecordHasJSSetMethods`, `CheckSetRecordHasJSMapMethods`):** These macros check if the `keys` and `has` methods of a `SetRecord` are the native implementations from `Set.prototype` or `Map.prototype`. This allows for optimized code paths when dealing with actual `Set` and `Map` instances.

* **`ShrinkOrderedHashSetIfNeeded`:** A macro that checks if an `OrderedHashSet` can be shrunk to save memory and calls `OrderedHashSetShrink` if necessary.

**Relationship to JavaScript Functionality:**

This Torque code directly implements the core logic behind JavaScript's `Set` and `Map` objects. Here's how some of the elements relate:

* **`Set` operations:**
    * `AddToSetTable` is used internally when you call `mySet.add(value)`.
    * `TableHasKey` is used by `mySet.has(value)`.
    * `DeleteFromSetTable` is used by `mySet.delete(value)`.
    * The iterator structures (`UnmodifiedOrderedHashSetIterator`, `OrderedHashSetIterator`) are used when you iterate over a `Set` using `for...of`, `mySet.keys()`, `mySet.values()`, or `mySet.entries()`.
    * `GetSetRecord` is used when functions expect a Set-like object as an argument.

* **`Map` operations:**
    * `TableHasKey` (the version for `OrderedHashMap`) is used by `myMap.has(key)`.
    * `UnsafeStoreValueInOrderedHashMapEntry` is involved when setting values in a `Map` (`myMap.set(key, value)`).
    * The `UnmodifiedOrderedHashMapIterator` is used for optimized iteration over `Map` entries.

**JavaScript Examples:**

```javascript
// Set examples
const mySet = new Set();
mySet.add(1); // Internally uses AddToSetTable
mySet.has(1); // Internally uses TableHasKey
mySet.delete(1); // Internally uses DeleteFromSetTable

for (const item of mySet) { // Internally uses the iterator structures
  console.log(item);
}

// Map examples
const myMap = new Map();
myMap.set('a', 1); // Internally uses UnsafeStoreValueInOrderedHashMapEntry
myMap.has('a'); // Internally uses TableHasKey (for OrderedHashMap)

for (const [key, value] of myMap) { // Internally uses the iterator structures
  console.log(key, value);
}

// Example where GetSetRecord might be used (though not directly callable by user code)
function checkIfHasSizeAndMethods(potentialSet) {
  // V8 internally uses something similar to GetSetRecord to validate 'potentialSet'
  if (typeof potentialSet !== 'object' || potentialSet === null) {
    throw new TypeError('Argument is not an object');
  }
  if (typeof potentialSet.size !== 'number' || isNaN(potentialSet.size)) {
    throw new TypeError('Size is NaN');
  }
  if (typeof potentialSet.has !== 'function') {
    throw new TypeError('has is not a function');
  }
  if (typeof potentialSet.keys !== 'function') {
    throw new TypeError('keys is not a function');
  }
  console.log("Looks like a Set!");
}

checkIfHasSizeAndMethods(new Set()); // Works
// checkIfHasSizeAndMethods({}); // Would likely throw errors internally similar to GetSetRecord
```

**Code Logic Inference (Hypothetical):**

**Scenario:** Adding an element to a `Set`.

**Assumption:** We have an `OrderedHashSet` representing a `Set` object. It has some existing elements.

**Input:**
* `context`: The current V8 execution context.
* `orderedHashSet`: An `OrderedHashSet` object, e.g., representing the set `{1, 2}`.
* `objectToAdd`: The JavaScript object to add, e.g., the number `3`.
* `hashString`: The string representation of the object to add (used for hashing), e.g., `"3"`.

**Macro Call:** `CollectionsBuiltinsAssembler::AddToSetTable(context)(orderedHashSet, objectToAdd, hashString)`

**Output:**
* A modified `OrderedHashSet` object. This new `OrderedHashSet` will contain the original elements plus the new element `3`. The internal structure of the hash table might be modified (e.g., a new bucket allocated) to accommodate the new element.

**Scenario:** Checking if a `Map` has a key.

**Assumption:** We have an `OrderedHashMap` representing a `Map` object.

**Input:**
* `context`: The current V8 execution context.
* `orderedHashMap`: An `OrderedHashMap` object, e.g., representing the map `{'a': 1, 'b': 2}`.
* `keyToCheck`: The JavaScript object to check as a key, e.g., the string `"a"`.

**Macro Call:** `CollectionsBuiltinsAssembler::TableHasKey(context)(orderedHashMap, keyToCheck)`

**Output:**
* A boolean value: `true` if the key exists in the `OrderedHashMap`, `false` otherwise. In this case, the output would be `true`.

**Common Programming Errors (from a V8 perspective):**

This code primarily deals with internal implementation, so it doesn't directly prevent common *user-level* JavaScript errors in the way syntax or type checking does. However, it *does* enforce the internal consistency and correctness of the `Set` and `Map` implementations, which indirectly prevents issues.

Here are some examples of how the logic in this file helps prevent potential problems:

1. **Incorrect assumptions about Set/Map-like objects:** The `GetSetRecord` macro ensures that objects treated as Sets by internal V8 code actually have the necessary `size`, `has`, and `keys` properties that behave like those of a real `Set`. This prevents unexpected behavior or crashes if a poorly implemented "Set-like" object is encountered.

   **Example of what could go wrong without such checks:** If V8 assumed an object had a `has` method without verifying it, and the object didn't have such a method or it was not a function, calling it would lead to a runtime error.

2. **Inconsistent iteration behavior:** The distinction between the "Unmodified" and regular iterators ensures that V8 can optimize iteration when the underlying collection isn't being changed. If the wrong iterator were used in a scenario where modifications occur, it could lead to:
   * **Skipping elements:** If elements are added during iteration with an "Unmodified" iterator.
   * **Processing elements multiple times:** If elements are deleted and re-added during iteration.
   * **Crashes or unpredictable behavior:** If internal data structures are accessed in an inconsistent state due to concurrent modifications.

3. **Memory management issues:** The `OrderedHashSetShrink` macro helps to reclaim memory when a `Set` becomes sparse after deletions. Without such mechanisms, `Set` objects could consume more memory than necessary.

4. **Internal state corruption:** The careful management of the hash tables (adding, deleting, resizing) ensures the internal data structures of `Set` and `Map` remain consistent. Errors in these operations could lead to data loss or incorrect results when querying the collections.

In summary, this Torque code is a crucial part of V8's implementation of JavaScript's `Set` and `Map` collections. It defines the internal data structures and algorithms that make these collections efficient and reliable. While it doesn't directly prevent user-level syntax errors, it ensures the underlying logic is sound, which indirectly prevents many potential runtime issues and inconsistencies when using these fundamental JavaScript data structures.

Prompt: 
```
这是目录为v8/src/builtins/collections.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/builtins/builtins-collections-gen.h'

namespace collections {

const kSetPrototypeValues: constexpr BuiltinsName
    generates 'Builtin::kSetPrototypeValues';
const kSetPrototypeHas: constexpr BuiltinsName
    generates 'Builtin::kSetPrototypeHas';
const kMapPrototypeKeys: constexpr BuiltinsName
    generates 'Builtin::kMapPrototypeKeys';
const kMapPrototypeHas: constexpr BuiltinsName
    generates 'Builtin::kMapPrototypeHas';

@export
struct SetRecord {
  // SetRecord.[[Set]]
  object: JSReceiver;

  // SetRecord.[[Size]]
  // a non-negative integer or +∞
  size: Number;

  // SetRecord.[[Has]]
  has: JSAny;

  // SetRecord.[[Keys]]
  keys: JSAny;
}

extern macro CodeStubAssembler::CloneFixedArray(
    FixedArrayBase, constexpr ExtractFixedArrayFlag): FixedArrayBase;

extern macro CollectionsBuiltinsAssembler::AddToSetTable(
    implicit context: Context)(OrderedHashSet, Object, String): OrderedHashSet;

extern macro CollectionsBuiltinsAssembler::TableHasKey(
    implicit context: Context)(OrderedHashSet, Object): bool;
extern macro CollectionsBuiltinsAssembler::TableHasKey(
    implicit context: Context)(OrderedHashMap, Object): bool;

extern macro CollectionsBuiltinsAssembler::DeleteFromSetTable(
    implicit context: Context)(OrderedHashSet, Object): Smi labels NotFound;

extern runtime OrderedHashSetShrink(implicit context: Context)(OrderedHashSet):
    OrderedHashSet;

// Direct iteration helpers.
@export
struct KeyIndexPair {
  key: JSAny;
  index: intptr;
}

@export
struct OrderedHashSetIndexPair {
  table: OrderedHashSet;
  index: intptr;
}

extern macro CollectionsBuiltinsAssembler::NextKeyIndexPairUnmodifiedTable(
    OrderedHashSet, int32, int32, intptr): KeyIndexPair labels Done;

// The underlying table must not be resized during iteration!
struct UnmodifiedOrderedHashSetIterator {
  macro Next(): JSAny labels Done {
    this.current = NextKeyIndexPairUnmodifiedTable(
        this.table, this.numBuckets, this.usedCapacity, this.current.index)
        otherwise Done;
    return this.current.key;
  }
  const table: OrderedHashSet;
  const numBuckets: int32;
  const usedCapacity: int32;
  current: KeyIndexPair;
}

extern macro CollectionsBuiltinsAssembler::TransitionOrderedHashSetNoUpdate(
    OrderedHashSet, intptr): OrderedHashSetIndexPair;

extern macro CollectionsBuiltinsAssembler::NextKeyIndexPair(
    OrderedHashSet, intptr): KeyIndexPair labels Done;

// The underlying table can be resized during iteration.
struct OrderedHashSetIterator {
  macro Next(): JSAny labels Done {
    // Transition the table and index in case it was modified during iteration.
    const tableAndIndex =
        TransitionOrderedHashSetNoUpdate(this.table, this.current.index);
    this.table = tableAndIndex.table;
    this.current.index = tableAndIndex.index;
    this.current = NextKeyIndexPair(this.table, this.current.index)
        otherwise Done;
    return this.current.key;
  }
  table: OrderedHashSet;
  current: KeyIndexPair;
}

macro LoadOrderedHashTableMetadata(
    table: OrderedHashMap|OrderedHashSet, fieldIndex: constexpr int32): int32 {
  return Convert<int32>(UnsafeCast<Smi>(table.objects[fieldIndex]));
}

const kOrderedHashSetNumberOfBucketsIndex:
    constexpr int32 generates 'OrderedHashSet::NumberOfBucketsIndex()';
const kOrderedHashSetNumberOfElementsIndex:
    constexpr int32 generates 'OrderedHashSet::NumberOfElementsIndex()';
const kOrderedHashSetNumberOfDeletedElementsIndex: constexpr int32
    generates 'OrderedHashSet::NumberOfDeletedElementsIndex()';

macro NewUnmodifiedOrderedHashSetIterator(table: OrderedHashSet):
    UnmodifiedOrderedHashSetIterator {
  const numBuckets =
      LoadOrderedHashTableMetadata(table, kOrderedHashSetNumberOfBucketsIndex);
  const numElements =
      LoadOrderedHashTableMetadata(table, kOrderedHashSetNumberOfElementsIndex);
  const numDeleted = LoadOrderedHashTableMetadata(
      table, kOrderedHashSetNumberOfDeletedElementsIndex);
  const usedCapacity = numElements + numDeleted;
  return UnmodifiedOrderedHashSetIterator{
    table: table,
    numBuckets: numBuckets,
    usedCapacity: usedCapacity,
    current: KeyIndexPair {
      key:
        Undefined, index: 0
    }
  };
}

macro NewOrderedHashSetIterator(table: OrderedHashSet):
    OrderedHashSetIterator {
  return OrderedHashSetIterator{
    table: table,
    current: KeyIndexPair {
      key:
        Undefined, index: 0
    }
  };
}

@export
struct KeyValueIndexTuple {
  key: JSAny;
  value: JSAny;
  index: intptr;
}
extern macro
    CollectionsBuiltinsAssembler::NextKeyValueIndexTupleUnmodifiedTable(
        OrderedHashMap, int32, int32, intptr): KeyValueIndexTuple labels Done;

extern macro CollectionsBuiltinsAssembler::NextKeyValueIndexTuple(
    OrderedHashMap, intptr): KeyValueIndexTuple labels Done;

extern macro
    CollectionsBuiltinsAssembler::UnsafeStoreValueInOrderedHashMapEntry(
        OrderedHashMap, Object, intptr): void;

const kOrderedHashMapEntrySize:
    constexpr int32 generates 'OrderedHashMap::kEntrySize';

// The underlying table must not be resized during iteration!
struct UnmodifiedOrderedHashMapIterator {
  macro Next(): KeyValuePair labels Done {
    this.current = NextKeyValueIndexTupleUnmodifiedTable(
        this.table, this.numBuckets, this.usedCapacity, this.current.index)
        otherwise Done;
    return KeyValuePair{key: this.current.key, value: this.current.value};
  }

  macro UnsafeStoreValueAtCurrentEntry(value: Object): void {
    // There is no current entry if the iterator is not yet advanced. The
    // current entry is at the previous index, as we've already advanced the
    // index.
    dcheck(this.current.index > 0);
    const entry =
        (Convert<int32>(this.current.index) - 1) * kOrderedHashMapEntrySize +
        this.numBuckets;
    UnsafeStoreValueInOrderedHashMapEntry(
        this.table, value, Convert<intptr>(entry));
  }

  const table: OrderedHashMap;
  const numBuckets: int32;
  const usedCapacity: int32;
  current: KeyValueIndexTuple;
}

const kOrderedHashMapNumberOfBucketsIndex:
    constexpr int32 generates 'OrderedHashMap::NumberOfBucketsIndex()';
const kOrderedHashMapNumberOfElementsIndex:
    constexpr int32 generates 'OrderedHashMap::NumberOfElementsIndex()';
const kOrderedHashMapNumberOfDeletedElementsIndex: constexpr int32
    generates 'OrderedHashMap::NumberOfDeletedElementsIndex()';

macro NewUnmodifiedOrderedHashMapIterator(table: OrderedHashMap):
    UnmodifiedOrderedHashMapIterator {
  const numBuckets =
      LoadOrderedHashTableMetadata(table, kOrderedHashMapNumberOfBucketsIndex);
  const numElements =
      LoadOrderedHashTableMetadata(table, kOrderedHashMapNumberOfElementsIndex);
  const numDeleted = LoadOrderedHashTableMetadata(
      table, kOrderedHashMapNumberOfDeletedElementsIndex);
  const usedCapacity = numElements + numDeleted;
  return UnmodifiedOrderedHashMapIterator{
    table: table,
    numBuckets: numBuckets,
    usedCapacity: usedCapacity,
    current: KeyValueIndexTuple {
      key:
        Undefined, value: Undefined, index: 0
    }
  };
}

@export
macro LoadKeyValuePairNoSideEffects(implicit context: Context)(o: JSAny):
    KeyValuePair labels MayHaveSideEffects {
  typeswitch (o) {
    case (a: FastJSArray): {
      const length: Smi = a.length;
      typeswitch (a.elements) {
        case (elements: FixedArray): {
          return KeyValuePair{
            key: length > 0 ? array::LoadElementOrUndefined(elements, 0) :
                              Undefined,
            value: length > 1 ? array::LoadElementOrUndefined(elements, 1) :
                                Undefined
          };
        }
        case (elements: FixedDoubleArray): {
          return KeyValuePair{
            key: length > 0 ? array::LoadElementOrUndefined(elements, 0) :
                              Undefined,
            value: length > 1 ? array::LoadElementOrUndefined(elements, 1) :
                                Undefined
          };
        }
        case (FixedArrayBase): deferred {
          unreachable;
        }
      }
    }
    case (JSAny): {
      goto MayHaveSideEffects;
    }
  }
}

@export
transitioning macro LoadKeyValuePair(implicit context: Context)(o: JSAny):
    KeyValuePair {
  try {
    return LoadKeyValuePairNoSideEffects(o) otherwise Generic;
  } label Generic {
    const o = Cast<JSReceiver>(o)
        otherwise ThrowTypeError(MessageTemplate::kIteratorValueNotAnObject, o);
    return KeyValuePair{
      key: GetProperty(o, Convert<Smi>(0)),
      value: GetProperty(o, Convert<Smi>(1))
    };
  }
}

// https://tc39.es/proposal-set-methods/#sec-getsetrecord
transitioning macro GetSetRecord(
    implicit context: Context)(obj: JSAny,
    methodName: constexpr string): SetRecord {
  // 1. If obj is not an Object, throw a TypeError exception.
  const obj = Cast<JSReceiver>(obj)
      otherwise ThrowTypeError(MessageTemplate::kArgumentIsNonObject, methodName);

  // 2. Let rawSize be ? Get(obj, "size").
  const rawSize = GetProperty(obj, kSizeString);

  // 3. Let numSize be ? ToNumber(rawSize).
  const numSize = ToNumber_Inline(rawSize);
  if (NumberIsNaN(numSize)) {
    // 4. NOTE: If rawSize is undefined, then numSize will be NaN.
    // 5. If numSize is NaN, throw a TypeError exception.
    ThrowTypeError(MessageTemplate::kSizeIsNaN);
  }

  // 6. Let intSize be ! ToIntegerOrInfinity(numSize).
  const intSize = ToInteger_Inline(numSize);

  // 7. If intSize < 0, throw a RangeError exception.
  if (intSize < 0) {
    ThrowRangeError(MessageTemplate::kInvalidSizeValue, intSize);
  }

  // 8. Let has be ? Get(obj, "has").
  let has = GetProperty(obj, kHasString);

  // 9. If IsCallable(has) is false, throw a TypeError exception.
  has = Cast<Callable>(has)
      otherwise ThrowCalledNonCallable(kHasString);

  // 10. Let keys be ? Get(obj, "keys").
  let keys = GetProperty(obj, kKeysString);

  // 11. If IsCallable(keys) is false, throw a TypeError exception.
  keys = Cast<Callable>(keys)
      otherwise ThrowCalledNonCallable(kKeysString);

  // 12. Return a new Set Record { [[Set]]: obj, [[Size]]: intSize, [[Has]]:
  // has, [[Keys]]: keys }.
  return SetRecord{object: obj, size: intSize, has: has, keys: keys};
}

// https://tc39.es/proposal-set-methods/#sec-getkeysiterator
transitioning macro GetKeysIterator(
    implicit context: Context)(set: JSReceiver,
    keys: Callable): iterator::IteratorRecord {
  // 1. Let keysIter be ? Call(setRec.[[Keys]], setRec.[[Set]]).
  const keysIter = Call(context, keys, set);

  // 2. If keysIter is not an Object, throw a TypeError exception.
  const keysIterObj = Cast<JSReceiver>(keysIter)
      otherwise ThrowTypeError(MessageTemplate::kKeysMethodInvalid);

  // 3. Let nextMethod be ? Get(keysIter, "next").
  const nextMethod = GetProperty(keysIter, kNextString);

  // 4. If IsCallable(nextMethod) is false, throw a TypeError exception.
  Cast<Callable>(nextMethod)
      otherwise ThrowCalledNonCallable(kNextString);

  // 5. Return a new Iterator Record { [[Iterator]]: keysIter, [[NextMethod]]:
  // nextMethod, [[Done]]: false }.
  return iterator::IteratorRecord{object: keysIterObj, next: nextMethod};
}

macro CheckSetRecordHasJSSetMethods(setRecord: SetRecord):
    void labels HasUserProvidedMethods {
  const keys =
      Cast<JSFunction>(setRecord.keys) otherwise HasUserProvidedMethods;
  const has = Cast<JSFunction>(setRecord.has) otherwise HasUserProvidedMethods;
  if (!(TaggedEqual(
            keys.shared_function_info.untrusted_function_data,
            SmiConstant(kSetPrototypeValues)) &&
        TaggedEqual(
            has.shared_function_info.untrusted_function_data,
            SmiConstant(kSetPrototypeHas))))
    goto HasUserProvidedMethods;
}

macro CheckSetRecordHasJSMapMethods(setRecord: SetRecord):
    void labels HasUserProvidedMethods {
  const keys =
      Cast<JSFunction>(setRecord.keys) otherwise HasUserProvidedMethods;
  const has = Cast<JSFunction>(setRecord.has) otherwise HasUserProvidedMethods;
  if (!(TaggedEqual(
            keys.shared_function_info.untrusted_function_data,
            SmiConstant(kMapPrototypeKeys)) &&
        TaggedEqual(
            has.shared_function_info.untrusted_function_data,
            SmiConstant(kMapPrototypeHas))))
    goto HasUserProvidedMethods;
}

macro ShrinkOrderedHashSetIfNeeded(
    implicit context: Context)(numberOfElements: Smi,
    resultSetData: OrderedHashSet): OrderedHashSet {
  dcheck(
      Convert<int32>(numberOfElements) ==
      LoadOrderedHashTableMetadata(
          resultSetData, kOrderedHashSetNumberOfElementsIndex));
  let result = resultSetData;

  // Shrink the result table if # of element is less than # buckets/2
  const numberOfBuckets =
      LoadOrderedHashTableMetadata(result, kOrderedHashSetNumberOfBucketsIndex);
  if (Convert<int32>(numberOfElements) < (numberOfBuckets / 2)) {
    result = OrderedHashSetShrink(result);
  }
  return result;
}

struct StableJSSetBackingTableWitness {
  macro GetTable(): StableOrderedHashSet {
    return this.unstable;
  }

  macro ReloadTable(): void {
    this.unstable =
        Cast<StableOrderedHashSet>(this.collection.table) otherwise unreachable;
  }

  macro LoadSize(): int32 {
    return LoadOrderedHashTableMetadata(
        this.unstable, kOrderedHashSetNumberOfElementsIndex);
  }

  macro HasKey(implicit context: Context)(key: Object): bool {
    return TableHasKey(this.unstable, key);
  }

  const collection: JSSet;
  unstable: StableOrderedHashSet;
}

struct StableJSMapBackingTableWitness {
  macro GetTable(): StableOrderedHashMap {
    return this.unstable;
  }

  macro LoadSize(): int32 {
    return LoadOrderedHashTableMetadata(
        this.unstable, kOrderedHashMapNumberOfElementsIndex);
  }

  macro HasKey(implicit context: Context)(key: Object): bool {
    return TableHasKey(this.unstable, key);
  }

  const collection: JSMap;
  unstable: StableOrderedHashMap;
}

macro NewStableBackingTableWitness(o: JSSet):
    StableJSSetBackingTableWitness {
  return StableJSSetBackingTableWitness{
    collection: o,
    unstable: Cast<StableOrderedHashSet>(o.table) otherwise unreachable
  };
}

macro NewStableBackingTableWitness(o: JSMap):
    StableJSMapBackingTableWitness {
  return StableJSMapBackingTableWitness{
    collection: o,
    unstable: Cast<StableOrderedHashMap>(o.table) otherwise unreachable
  };
}

}  // namespace collections

"""

```