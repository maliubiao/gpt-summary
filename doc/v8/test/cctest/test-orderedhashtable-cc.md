Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/cctest/test-orderedhashtable.cc`. The request has several constraints:

1. **List the functionalities:** Identify the main purpose and actions performed by the code.
2. **Torque source check:** Determine if the file would be a Torque file based on its extension.
3. **JavaScript relevance:** If the code relates to JavaScript functionality, provide a JavaScript example.
4. **Code logic inference:** If there are logical code sections, provide example inputs and outputs.
5. **Common programming errors:** Identify potential user errors related to the code's functionality.
6. **Summarize the functionality (Part 1):** Provide a concise overview of the code's purpose as the first part of a three-part explanation.

Let's break down the code to address each point:

- **Includes:** The code includes headers for V8 objects and the CCTEST framework, indicating it's a unit test for V8's internal data structures.
- **Helper functions:**  `GetIsolateFrom`, `CopyHashCode`, and `Verify` are utility functions for getting the isolate, copying hash codes, and verifying heap objects, respectively.
- **Templated `Add` functions:** Overloaded `Add` functions exist for different ordered hash table types (`OrderedHashMap`, `OrderedHashSet`, `OrderedNameDictionary`). This suggests the tests are designed to be generic across these types.
- **Templated `HasKey` functions:** Similar to `Add`, overloaded `HasKey` functions check for key existence in the different hash table types.
- **Templated `Delete` functions:** Overloaded `Delete` functions handle key deletion, with a specific implementation for `OrderedNameDictionary`.
- **`TEST` macros:**  The code uses `TEST` macros from CCTEST, indicating these are unit tests. The names of the tests (e.g., `SmallOrderedHashSetInsertion`, `SmallOrderedHashMapInsertion`, `OrderedHashTableInsertion`, `OrderedHashMapDeletion`) clearly point to the functionalities being tested.

Based on this analysis:

1. **Functionalities:** The code tests the insertion, retrieval (via `HasKey`), and deletion of key-value pairs (or just keys for sets) in different types of ordered hash tables: `SmallOrderedHashSet`, `SmallOrderedHashMap`, and `OrderedHashMap`. It also tests the behavior when inserting elements with duplicate hash codes and the growth of these hash tables.
2. **Torque source check:** The file extension is `.cc`, not `.tq`, so it's not a Torque source file.
3. **JavaScript relevance:** Ordered hash tables are fundamental to how JavaScript objects and Maps are implemented. The tested functionalities directly correspond to JavaScript's object property access and `Map` operations.
4. **Code logic inference:**  The tests use assertions (`CHECK_EQ`, `CHECK`) to verify expected states after operations like insertion and deletion. For example, after adding a key, the test checks if the `NumberOfElements` has increased and if `HasKey` returns true.
5. **Common programming errors:** Users might try to access or delete keys that don't exist, or might be unaware of the implications of objects having the same hash code.
6. **Summary (Part 1):** The code defines unit tests for various ordered hash table implementations in V8, specifically focusing on insertion, checking for key existence, and deletion operations. These tests cover different scenarios, including adding new and existing keys, handling duplicate hash codes, and verifying the growth behavior of the hash tables.

Now, let's formulate the response based on these observations.
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <utility>

#include "src/objects/objects-inl.h"
#include "src/objects/ordered-hash-table-inl.h"
#include "test/cctest/cctest.h"

namespace v8 {
namespace internal {
namespace test_orderedhashtable {

static Isolate* GetIsolateFrom(LocalContext* context) {
  return reinterpret_cast<Isolate*>((*context)->GetIsolate());
}

void CopyHashCode(DirectHandle<JSReceiver> from, DirectHandle<JSReceiver> to) {
  int hash = Smi::ToInt(Object::GetHash(*from));
  to->SetIdentityHash(hash);
}

void Verify(Isolate* isolate, DirectHandle<HeapObject> obj) {
#if VERIFY_HEAP
  Object::ObjectVerify(*obj, isolate);
#endif
}

// Helpers to abstract over differences in interfaces of the different ordered
// datastructures

template <typename T>
Handle<T> Add(Isolate* isolate, Handle<T> table, Handle<String> key1,
              Handle<String> value1, PropertyDetails details);

template <>
Handle<OrderedHashMap> Add(Isolate* isolate, Handle<OrderedHashMap> table,
                           Handle<String> key, Handle<String> value,
                           PropertyDetails details) {
  return OrderedHashMap::Add(isolate, table, key, value).ToHandleChecked();
}

template <>
Handle<OrderedHashSet> Add(Isolate* isolate, Handle<OrderedHashSet> table,
                           Handle<String> key, Handle<String> value,
                           PropertyDetails details) {
  return OrderedHashSet::Add(isolate, table, key).ToHandleChecked();
}

template <>
Handle<OrderedNameDictionary> Add(Isolate* isolate,
                                  Handle<OrderedNameDictionary> table,
                                  Handle<String> key, Handle<String> value,
                                  PropertyDetails details) {
  return OrderedNameDictionary::Add(isolate, table, key, value, details)
      .ToHandleChecked();
}

// version for
// OrderedHashMap, OrderedHashSet
template <typename T>
bool HasKey(Isolate* isolate, Handle<T> table, Tagged<Object> key) {
  return T::HasKey(isolate, *table, key);
}

template <>
bool HasKey(Isolate* isolate, Handle<OrderedNameDictionary> table,
            Tagged<Object> key) {
  return table->FindEntry(isolate, key).is_found();
}

// version for
// OrderedHashTable, OrderedHashSet
template <typename T>
Handle<T> Delete(Isolate* isolate, Handle<T> table, Tagged<Object> key) {
  T::Delete(isolate, *table, key);
  return table;
}

template <>
Handle<OrderedNameDictionary> Delete(Isolate* isolate,
                                     Handle<OrderedNameDictionary> table,
                                     Tagged<Object> key) {
  // OrderedNameDictionary doesn't have Delete, but only DeleteEntry, which
  // requires the key to be deleted to be present
  InternalIndex entry = table->FindEntry(isolate, key);
  if (entry.is_not_found()) return table;

  return OrderedNameDictionary::DeleteEntry(isolate, table, entry);
}

TEST(SmallOrderedHashSetInsertion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashSet> set = factory->NewSmallOrderedHashSet();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfElements());

  // Add a new key.
  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  CHECK(!set->HasKey(isolate, key1));
  set = SmallOrderedHashSet::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));

  // Add existing key.
  set = SmallOrderedHashSet::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));

  DirectHandle<String> key2 = factory->NewStringFromAsciiChecked("foo");
  CHECK(!set->HasKey(isolate, key2));
  set = SmallOrderedHashSet::Add(isolate, set, key2).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(2, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));

  set = SmallOrderedHashSet::Add(isolate, set, key2).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(2, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));

  DirectHandle<Symbol> key3 = factory->NewSymbol();
  CHECK(!set->HasKey(isolate, key3));
  set = SmallOrderedHashSet::Add(isolate, set, key3).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(3, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
  CHECK(set->HasKey(isolate, key3));

  set = SmallOrderedHashSet::Add(isolate, set, key3).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(3, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
  CHECK(set->HasKey(isolate, key3));

  DirectHandle<Object> key4 = factory->NewHeapNumber(42.0);
  CHECK(!set->HasKey(isolate, key4));
  set = SmallOrderedHashSet::Add(isolate, set, key4).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(4, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
  CHECK(set->HasKey(isolate, key3));
  CHECK(set->HasKey(isolate, key4));

  set = SmallOrderedHashSet::Add(isolate, set, key4).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(4, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
  CHECK(set->HasKey(isolate, key3));
  CHECK(set->HasKey(isolate, key4));
}

TEST(SmallOrderedHashMapInsertion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashMap> map = factory->NewSmallOrderedHashMap();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());

  // Add a new key.
  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  DirectHandle<Smi> value1(Smi::FromInt(1), isolate);
  CHECK(!map->HasKey(isolate, key1));
  map = SmallOrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));

  // Add existing key.
  map = SmallOrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));

  DirectHandle<String> key2 = factory->NewStringFromAsciiChecked("foo");
  DirectHandle<String> value = factory->NewStringFromAsciiChecked("foo");
  CHECK(!map->HasKey(isolate, key2));
  map = SmallOrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));

  map = SmallOrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));

  DirectHandle<Symbol> key3 = factory->NewSymbol();
  CHECK(!map->HasKey(isolate, key3));
  map = SmallOrderedHashMap::Add(isolate, map, key3, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(3, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));

  map = SmallOrderedHashMap::Add(isolate, map, key3, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(3, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));

  DirectHandle<Object> key4 = factory->NewHeapNumber(42.0);
  CHECK(!map->HasKey(isolate, key4));
  map = SmallOrderedHashMap::Add(isolate, map, key4, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(4, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));
  CHECK(map->HasKey(isolate, key4));

  map = SmallOrderedHashMap::Add(isolate, map, key4, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(4, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));
  CHECK(map->HasKey(isolate, key4));
}

TEST(SmallOrderedHashSetDuplicateHashCode) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashSet> set = factory->NewSmallOrderedHashSet();
  DirectHandle<JSObject> key1 = factory->NewJSObjectWithNullProto();
  set = SmallOrderedHashSet::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));

  DirectHandle<JSObject> key2 = factory->NewJSObjectWithNullProto();
  CopyHashCode(key1, key2);

  set = SmallOrderedHashSet::Add(isolate, set, key2).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(2, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
}

TEST(SmallOrderedHashMapDuplicateHashCode) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashMap> map = factory->NewSmallOrderedHashMap();
  DirectHandle<JSObject> value = factory->NewJSObjectWithNullProto();
  DirectHandle<JSObject> key1 = factory->NewJSObjectWithNullProto();
  map = SmallOrderedHashMap::Add(isolate, map, key1, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));

  DirectHandle<JSObject> key2 = factory->NewJSObjectWithNullProto();
  CopyHashCode(key1, key2);

  CHECK(!Object::SameValue(*key1, *key2));
  Tagged<Object> hash1 = Object::GetHash(*key1);
  Tagged<Object> hash2 = Object::GetHash(*key2);
  CHECK_EQ(hash1, hash2);

  map = SmallOrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
}

TEST(SmallOrderedHashSetGrow) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashSet> set = factory->NewSmallOrderedHashSet();
  std::vector<Handle<Object>> keys;
  for (int i = 0; i < 254; i++) {
    Handle<Smi> key(Smi::FromInt(i), isolate);
    keys.push_back(key);
  }

  for (size_t i = 0; i < 4; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 4; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(4, set->NumberOfElements());
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 4; i < 8; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 8; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(8, set->NumberOfElements());
  CHECK_EQ(4, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 8; i < 16; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 16; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(16, set->NumberOfElements());
  CHECK_EQ(8, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 16; i < 32; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 32; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(32, set->NumberOfElements());
  CHECK_EQ(16, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 32; i < 64; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 64; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(64, set->NumberOfElements());
  CHECK_EQ(32, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 64; i < 128; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 128; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(128, set->NumberOfElements());
  CHECK_EQ(64, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 128; i < 254; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 254; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(254, set->NumberOfElements());
  CHECK_EQ(127, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);
}

TEST(SmallOrderedHashMapGrow) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashMap> map = factory->NewSmallOrderedHashMap();
  std::vector<Handle<Object>> keys;
  for (int i = 0; i < 254; i++) {
    Handle<Smi> key(Smi::FromInt(i), isolate);
    keys.push_back(key);
  }

  for (size_t i = 0; i < 4; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 4; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(4, map->NumberOfElements());
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 4; i < 8; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 8; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(8, map->NumberOfElements());
  CHECK_EQ(4, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 8; i < 16; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 16; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(16, map->NumberOfElements());
  CHECK_EQ(8, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 16; i < 32; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 32; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(32, map->NumberOfElements());
  CHECK_EQ(16, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 32; i < 64; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 64; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(64, map->NumberOfElements());
  CHECK_EQ(32, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 64; i < 128; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 128; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(128, map->NumberOfElements());
  CHECK_EQ(64, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 128; i < 254; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 254; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(254, map->NumberOfElements());
  CHECK_EQ(127, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);
}

TEST(OrderedHashTableInsertion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<OrderedHashMap> map = factory->NewOrderedHashMap();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());

  // Add a new key.
  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  DirectHandle<Smi> value1(Smi::FromInt(1), isolate);
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key1));
  map = OrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));

  // Add existing key.
  map = OrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));

  DirectHandle<String> key2 = factory->NewStringFromAsciiChecked("foo");
  DirectHandle<String> value = factory->NewStringFromAsciiChecked("bar");
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key2));
  map = OrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));

  map = OrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));

  DirectHandle<Symbol> key3 = factory->NewSymbol();
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key3));
  map = OrderedHashMap::Add(isolate, map, key3, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(3, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));

  map = OrderedHashMap::Add(isolate, map, key3, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(3, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));

  DirectHandle<Object> key4 = factory->NewHeapNumber(42.0);
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key4));
  map = OrderedHashMap::Add(isolate, map, key4, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(4, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key4));

  map = OrderedHashMap::Add(isolate, map, key4, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(4, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key4));
}

TEST(OrderedHashMapDuplicateHashCode) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<OrderedHashMap> map = factory->NewOrderedHashMap();
  DirectHandle<JSObject> key1 = factory->NewJSObjectWithNullProto();
  DirectHandle<JSObject> value = factory->NewJSObjectWithNullProto();
  map = OrderedHashMap::Add(isolate, map, key1, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));

  DirectHandle<JSObject> key2 = factory->NewJSObjectWithNullProto();
  CopyHashCode(key1, key2);

  map = OrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
}

TEST(OrderedHashMapDeletion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  DirectHandle<Smi> value1(Smi::FromInt(1), isolate);
  DirectHandle<String
### 提示词
```
这是目录为v8/test/cctest/test-orderedhashtable.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-orderedhashtable.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <utility>

#include "src/objects/objects-inl.h"
#include "src/objects/ordered-hash-table-inl.h"
#include "test/cctest/cctest.h"

namespace v8 {
namespace internal {
namespace test_orderedhashtable {

static Isolate* GetIsolateFrom(LocalContext* context) {
  return reinterpret_cast<Isolate*>((*context)->GetIsolate());
}

void CopyHashCode(DirectHandle<JSReceiver> from, DirectHandle<JSReceiver> to) {
  int hash = Smi::ToInt(Object::GetHash(*from));
  to->SetIdentityHash(hash);
}

void Verify(Isolate* isolate, DirectHandle<HeapObject> obj) {
#if VERIFY_HEAP
  Object::ObjectVerify(*obj, isolate);
#endif
}

// Helpers to abstract over differences in interfaces of the different ordered
// datastructures

template <typename T>
Handle<T> Add(Isolate* isolate, Handle<T> table, Handle<String> key1,
              Handle<String> value1, PropertyDetails details);

template <>
Handle<OrderedHashMap> Add(Isolate* isolate, Handle<OrderedHashMap> table,
                           Handle<String> key, Handle<String> value,
                           PropertyDetails details) {
  return OrderedHashMap::Add(isolate, table, key, value).ToHandleChecked();
}

template <>
Handle<OrderedHashSet> Add(Isolate* isolate, Handle<OrderedHashSet> table,
                           Handle<String> key, Handle<String> value,
                           PropertyDetails details) {
  return OrderedHashSet::Add(isolate, table, key).ToHandleChecked();
}

template <>
Handle<OrderedNameDictionary> Add(Isolate* isolate,
                                  Handle<OrderedNameDictionary> table,
                                  Handle<String> key, Handle<String> value,
                                  PropertyDetails details) {
  return OrderedNameDictionary::Add(isolate, table, key, value, details)
      .ToHandleChecked();
}

// version for
// OrderedHashMap, OrderedHashSet
template <typename T>
bool HasKey(Isolate* isolate, Handle<T> table, Tagged<Object> key) {
  return T::HasKey(isolate, *table, key);
}

template <>
bool HasKey(Isolate* isolate, Handle<OrderedNameDictionary> table,
            Tagged<Object> key) {
  return table->FindEntry(isolate, key).is_found();
}

// version for
// OrderedHashTable, OrderedHashSet
template <typename T>
Handle<T> Delete(Isolate* isolate, Handle<T> table, Tagged<Object> key) {
  T::Delete(isolate, *table, key);
  return table;
}

template <>
Handle<OrderedNameDictionary> Delete(Isolate* isolate,
                                     Handle<OrderedNameDictionary> table,
                                     Tagged<Object> key) {
  // OrderedNameDictionary doesn't have Delete, but only DeleteEntry, which
  // requires the key to be deleted to be present
  InternalIndex entry = table->FindEntry(isolate, key);
  if (entry.is_not_found()) return table;

  return OrderedNameDictionary::DeleteEntry(isolate, table, entry);
}

TEST(SmallOrderedHashSetInsertion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashSet> set = factory->NewSmallOrderedHashSet();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfElements());

  // Add a new key.
  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  CHECK(!set->HasKey(isolate, key1));
  set = SmallOrderedHashSet::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));

  // Add existing key.
  set = SmallOrderedHashSet::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));

  DirectHandle<String> key2 = factory->NewStringFromAsciiChecked("foo");
  CHECK(!set->HasKey(isolate, key2));
  set = SmallOrderedHashSet::Add(isolate, set, key2).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(2, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));

  set = SmallOrderedHashSet::Add(isolate, set, key2).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(2, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));

  DirectHandle<Symbol> key3 = factory->NewSymbol();
  CHECK(!set->HasKey(isolate, key3));
  set = SmallOrderedHashSet::Add(isolate, set, key3).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(3, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
  CHECK(set->HasKey(isolate, key3));

  set = SmallOrderedHashSet::Add(isolate, set, key3).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(3, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
  CHECK(set->HasKey(isolate, key3));

  DirectHandle<Object> key4 = factory->NewHeapNumber(42.0);
  CHECK(!set->HasKey(isolate, key4));
  set = SmallOrderedHashSet::Add(isolate, set, key4).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(4, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
  CHECK(set->HasKey(isolate, key3));
  CHECK(set->HasKey(isolate, key4));

  set = SmallOrderedHashSet::Add(isolate, set, key4).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(4, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
  CHECK(set->HasKey(isolate, key3));
  CHECK(set->HasKey(isolate, key4));
}

TEST(SmallOrderedHashMapInsertion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashMap> map = factory->NewSmallOrderedHashMap();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());

  // Add a new key.
  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  DirectHandle<Smi> value1(Smi::FromInt(1), isolate);
  CHECK(!map->HasKey(isolate, key1));
  map = SmallOrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));

  // Add existing key.
  map = SmallOrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));

  DirectHandle<String> key2 = factory->NewStringFromAsciiChecked("foo");
  DirectHandle<String> value = factory->NewStringFromAsciiChecked("foo");
  CHECK(!map->HasKey(isolate, key2));
  map = SmallOrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));

  map = SmallOrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));

  DirectHandle<Symbol> key3 = factory->NewSymbol();
  CHECK(!map->HasKey(isolate, key3));
  map = SmallOrderedHashMap::Add(isolate, map, key3, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(3, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));

  map = SmallOrderedHashMap::Add(isolate, map, key3, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(3, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));

  DirectHandle<Object> key4 = factory->NewHeapNumber(42.0);
  CHECK(!map->HasKey(isolate, key4));
  map = SmallOrderedHashMap::Add(isolate, map, key4, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(4, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));
  CHECK(map->HasKey(isolate, key4));

  map = SmallOrderedHashMap::Add(isolate, map, key4, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(4, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));
  CHECK(map->HasKey(isolate, key4));
}

TEST(SmallOrderedHashSetDuplicateHashCode) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashSet> set = factory->NewSmallOrderedHashSet();
  DirectHandle<JSObject> key1 = factory->NewJSObjectWithNullProto();
  set = SmallOrderedHashSet::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));

  DirectHandle<JSObject> key2 = factory->NewJSObjectWithNullProto();
  CopyHashCode(key1, key2);

  set = SmallOrderedHashSet::Add(isolate, set, key2).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(2, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
}

TEST(SmallOrderedHashMapDuplicateHashCode) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashMap> map = factory->NewSmallOrderedHashMap();
  DirectHandle<JSObject> value = factory->NewJSObjectWithNullProto();
  DirectHandle<JSObject> key1 = factory->NewJSObjectWithNullProto();
  map = SmallOrderedHashMap::Add(isolate, map, key1, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));

  DirectHandle<JSObject> key2 = factory->NewJSObjectWithNullProto();
  CopyHashCode(key1, key2);

  CHECK(!Object::SameValue(*key1, *key2));
  Tagged<Object> hash1 = Object::GetHash(*key1);
  Tagged<Object> hash2 = Object::GetHash(*key2);
  CHECK_EQ(hash1, hash2);

  map = SmallOrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
}

TEST(SmallOrderedHashSetGrow) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashSet> set = factory->NewSmallOrderedHashSet();
  std::vector<Handle<Object>> keys;
  for (int i = 0; i < 254; i++) {
    Handle<Smi> key(Smi::FromInt(i), isolate);
    keys.push_back(key);
  }

  for (size_t i = 0; i < 4; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 4; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(4, set->NumberOfElements());
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 4; i < 8; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 8; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(8, set->NumberOfElements());
  CHECK_EQ(4, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 8; i < 16; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 16; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(16, set->NumberOfElements());
  CHECK_EQ(8, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 16; i < 32; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 32; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(32, set->NumberOfElements());
  CHECK_EQ(16, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 32; i < 64; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 64; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(64, set->NumberOfElements());
  CHECK_EQ(32, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 64; i < 128; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 128; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(128, set->NumberOfElements());
  CHECK_EQ(64, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 128; i < 254; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 254; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(254, set->NumberOfElements());
  CHECK_EQ(127, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);
}

TEST(SmallOrderedHashMapGrow) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashMap> map = factory->NewSmallOrderedHashMap();
  std::vector<Handle<Object>> keys;
  for (int i = 0; i < 254; i++) {
    Handle<Smi> key(Smi::FromInt(i), isolate);
    keys.push_back(key);
  }

  for (size_t i = 0; i < 4; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 4; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(4, map->NumberOfElements());
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 4; i < 8; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 8; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(8, map->NumberOfElements());
  CHECK_EQ(4, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 8; i < 16; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 16; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(16, map->NumberOfElements());
  CHECK_EQ(8, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 16; i < 32; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 32; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(32, map->NumberOfElements());
  CHECK_EQ(16, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 32; i < 64; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 64; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(64, map->NumberOfElements());
  CHECK_EQ(32, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 64; i < 128; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 128; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(128, map->NumberOfElements());
  CHECK_EQ(64, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 128; i < 254; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 254; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(254, map->NumberOfElements());
  CHECK_EQ(127, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);
}

TEST(OrderedHashTableInsertion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<OrderedHashMap> map = factory->NewOrderedHashMap();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());

  // Add a new key.
  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  DirectHandle<Smi> value1(Smi::FromInt(1), isolate);
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key1));
  map = OrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));

  // Add existing key.
  map = OrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));

  DirectHandle<String> key2 = factory->NewStringFromAsciiChecked("foo");
  DirectHandle<String> value = factory->NewStringFromAsciiChecked("bar");
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key2));
  map = OrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));

  map = OrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));

  DirectHandle<Symbol> key3 = factory->NewSymbol();
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key3));
  map = OrderedHashMap::Add(isolate, map, key3, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(3, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));

  map = OrderedHashMap::Add(isolate, map, key3, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(3, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));

  DirectHandle<Object> key4 = factory->NewHeapNumber(42.0);
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key4));
  map = OrderedHashMap::Add(isolate, map, key4, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(4, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key4));

  map = OrderedHashMap::Add(isolate, map, key4, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(4, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key4));
}

TEST(OrderedHashMapDuplicateHashCode) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<OrderedHashMap> map = factory->NewOrderedHashMap();
  DirectHandle<JSObject> key1 = factory->NewJSObjectWithNullProto();
  DirectHandle<JSObject> value = factory->NewJSObjectWithNullProto();
  map = OrderedHashMap::Add(isolate, map, key1, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));

  DirectHandle<JSObject> key2 = factory->NewJSObjectWithNullProto();
  CopyHashCode(key1, key2);

  map = OrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
}

TEST(OrderedHashMapDeletion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  DirectHandle<Smi> value1(Smi::FromInt(1), isolate);
  DirectHandle<String> value = factory->NewStringFromAsciiChecked("bar");

  Handle<OrderedHashMap> map = factory->NewOrderedHashMap();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());

  // Delete from an empty hash table
  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  CHECK(!OrderedHashMap::Delete(isolate, *map, *key1));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key1));

  map = OrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));

  // Delete single existing key
  CHECK(OrderedHashMap::Delete(isolate, *map, *key1));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(1, map->NumberOfDeletedElements());
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key1));

  map = OrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(1, map->NumberOfDeletedElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));

  DirectHandle<String> key2 = factory->NewStringFromAsciiChecked("foo");
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key2));
  map = OrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK_EQ(1, map->NumberOfDeletedElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));

  DirectHandle<Symbol> key3 = factory->NewSymbol();
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key3));
  map = OrderedHashMap::Add(isolate, map, key3, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(3, map->NumberOfElements());
  CHECK_EQ(1, map->NumberOfDeletedElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));

  // Delete multiple existing keys
  CHECK(OrderedHashMap::Delete(isolate, *map, *key1));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK_EQ(2, map->NumberOfDeletedElements());
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));

  CHECK(OrderedHashMap::Delete(isolate, *map, *key2));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(3, map->NumberOfDeletedElements());
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));

  CHECK(OrderedHashMap::Delete(isolate, *map, *key3));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(4, map->NumberOfDeletedElements());
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key3));

  // Delete non existent key from non new hash table
  CHECK(!OrderedHashMap::Delete(isolate, *map, *key3));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(4, map->NumberOfDeletedElements());
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key3));

  // Delete non existent key from non empty hash table
  map = OrderedHashMap::Shrink(isolate, map);
  map = OrderedHashMap::Add(isolate, map, key1, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key3));
  CHECK(!OrderedHashMap::Delete(isolate, *map, *key2));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key3));
}

TEST(SmallOrderedHashMapDeletion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  DirectHandle<Smi> value1(Smi::FromInt(1), isolate);
  DirectHandle<String> value = factory->NewStringFromAsciiChecked("bar");

  Handle<SmallOrderedHashMap> map = factory->NewSmallOrderedHashMap();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());

  // Delete from an empty hash table
  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  CHECK(!SmallOrderedHashMap::Delete(isolate, *map, *key1));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(!map->HasKey(isolate, key1));

  map = SmallOrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(map->HasKey(isolate, key1));

  // Delete single existing key
  CHECK(SmallOrderedHashMap::Delete(isolate, *map, *key1));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(1, map->NumberOfDeletedElements());
  CHECK(!map->HasKey(isolate, key1));

  map = SmallOrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(1, map->NumberOfDeletedElements());
  CHECK(map->HasKey(isolate, key1));

  DirectHandle<String> key2 = factory->NewStringFromAsciiChecked("foo");
  CHECK(!map->HasKey(isolate, key2));
  map = SmallOrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK_EQ(1, map->NumberOfDeletedElements());
  CHECK(map->HasKey(isolate, key2));

  DirectHandle<Symbol> key3 = factory->NewSymbol();
  CHECK(!map->HasKey(isolate, key3));
  map = SmallOrderedHashMap::Add(isolate, map, key3, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(3, map->NumberOfElements());
  CHECK_EQ(1, map->NumberOfDeletedElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));

  // Delete multiple existing keys
  CHECK(SmallOrderedHashMap::Delete(isolate, *map, *key1));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK_EQ(2, map->NumberOfDeletedElements());
  CHECK(!map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));

  CHECK(SmallOrderedHashMap::Delete(isolate, *map, *key2));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(3, map->NumberOfDeletedElements());
  CHECK(!map->HasKey(isolate, key1));
  CHECK(!map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));

  CHECK(SmallOrderedHashMap::Delete(isolate, *map, *key3));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(4, map->NumberOfDeletedElements());
  CHECK(!map->HasKey(isolate, key1));
  CHECK(!map->HasKey(isolate, key2));
  CHECK(!map->HasKey(isolate, key3));

  // Delete non existent key from non new hash table
  CHECK(!SmallOrderedHashMap::Delete(isolate, *map, *key3));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(4, map->NumberOfDeletedElements());
  CHECK(!map->HasKey(isolate, key1));
  CHECK(!map->HasKey(isolate, key2));
  CHECK(!map->HasKey(isolate, key3));

  // Delete non existent key from non empty hash table
  map = SmallOrderedHashMap::Add(isolate, map, key1, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(!map->HasKey(isolate, key2));
  CHECK(!map->HasKey(isolate, key3));
  CHECK(!SmallOrderedHashMap::Delete(isolate, *map, *key2));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(!map->HasKey(isolate, key2));
  CHECK(!map->HasKey(isolate, key3));
}

TEST(OrderedHashMapDuplicateHashCodeDeletion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<OrderedHashMap> map = factory->NewOrderedHashMap();
  DirectHandle<JSObject> key1 = factory->NewJSObjectWithNullProto();
  DirectHandle<JSObject> value = factory->NewJSObjectWithNullProto();
  map = OrderedHashMap::Add(isolate, map, key1, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));

  DirectHandle<JSObject> key2 = factory->NewJSObjectWithNullProto();
  CopyHashCode(key1, key2);

  // We shouldn't be able to dele
```