Response:
Let's break down the thought process to analyze the provided Torque code.

1. **Identify the Core Purpose:** The filename `swiss-name-dictionary.tq` and the class name `SwissNameDictionary` strongly suggest this code implements a dictionary (or map) data structure. The "Name" in the name further hints that the keys are likely JavaScript identifiers (strings used as property names). The "Swiss" likely refers to the underlying hashing algorithm or data structure optimization.

2. **Recognize Torque:** The `.tq` extension and the syntax (`extern class`, `extern macro`, `@export macro`) immediately identify this as V8's Torque language. The initial comment confirms this. The key takeaway here is that Torque is a *code generation* language. It defines how C++ code should be generated. So, while we're looking at Torque, we need to understand its relationship to the underlying C++ implementation.

3. **Analyze the Class Definition:** The `SwissNameDictionary` class definition provides the basic structure:
    * `hash`:  Likely stores the hash of the key.
    * `capacity`: The total number of slots in the dictionary.
    * `meta_table`:  Seems to store metadata about the dictionary's state (e.g., used slots, deleted slots). The size hints at different encoding strategies.
    * `data_table`:  The core storage for key-value pairs. The `JSAny|TheHole` type indicates it can hold any JavaScript value or a special "empty" marker. The `capacity * 2` suggests each entry holds both the key and the value.
    * `ctrl_table`: Likely the "control table" used in the Swiss Table algorithm. It stores metadata (like hash prefixes) to quickly identify potential matches. The `capacity + swiss_table::kGroupWidth` is important for the grouping concept of Swiss Tables.
    * `property_details_table`: Stores additional information about the property (e.g., attributes like writable, enumerable).

4. **Examine the `swiss_table` Namespace:**  This namespace contains constants and macros related to the Swiss Table implementation. Key things to notice:
    * Constants like `kDataTableEntryCount`, `kMax1ByteMetaTableCapacity`, `kNotFoundSentinel` provide implementation details.
    * Macros like `LoadSwissNameDictionaryKey`, `StoreSwissNameDictionaryKeyAndValue`, and `SwissNameDictionarySetCtrl` provide access and manipulation methods for the dictionary's internal structures. These map directly to C++ inline functions.
    * The `runtime` namespace indicates calls to built-in V8 runtime functions (implemented in C++). This is crucial for understanding higher-level operations like adding, finding, and shrinking.

5. **Focus on Exported Macros:**  Macros marked with `@export` are intended to be used from other parts of the V8 codebase. These represent the main API of the `SwissNameDictionary`. Let's analyze the important ones:
    * `SwissNameDictionaryCapacityFor`: Calculates the initial or expanded capacity based on the requested space. The logic with power-of-two rounding and the `kGroupWidth` check is specific to Swiss Tables.
    * `SwissNameDictionaryMaxUsableCapacity`: Determines the effective usable space, accounting for the limitations of the Swiss Table algorithm.
    * `SwissNameDictionarySizeFor`: Calculates the total memory footprint of the dictionary.
    * `SwissNameDictionaryMetaTableSizePerEntryFor` and `SwissNameDictionaryMetaTableSizeFor`:  Deal with the metadata storage, revealing different sizes based on capacity.
    * `SwissNameDictionaryDataTableStartOffsetMT` and `SwissNameDictionaryCtrlTableStartOffsetMT`:  Calculate the memory offsets of the data and control tables.
    * `SwissNameDictionaryFindEntrySIMD` and `SwissNameDictionaryFindEntryPortable`:  Implement the core lookup operation, with SIMD and portable (non-SIMD) versions. This shows an optimization strategy.
    * `SwissNameDictionaryAddSIMD` and `SwissNameDictionaryAddPortable`: Implement the insertion operation, again with SIMD and portable versions.
    * `SwissNameDictionaryDelete`:  Implements the deletion operation and includes logic for potentially shrinking the dictionary.

6. **Analyze Internal Macros (without `@export`):** These provide insights into the inner workings:
    * `Probe`: Implements the probing logic for finding a slot in the hash table.
    * `FindEntry`:  The core search algorithm, using a `GroupLoader` (likely for SIMD/non-SIMD distinction).
    * `FindFirstEmpty`: Finds the first available slot for insertion.
    * `Add`:  The core insertion algorithm.
    * `SwissNameDictionaryDelete`: The internal deletion logic (the exported `SwissNameDictionaryDelete` seems to be a wrapper).

7. **Connect to JavaScript Functionality:**  Think about how JavaScript objects work. They are essentially dictionaries mapping property names (strings) to values. The `SwissNameDictionary` is very likely used as the underlying implementation for the properties of JavaScript objects.

8. **Illustrate with JavaScript Examples:** Come up with simple JavaScript code snippets that would directly trigger the functionality of the `SwissNameDictionary`. Creating objects and accessing/modifying properties are the key actions.

9. **Infer Code Logic and Provide Examples:** For key macros like `FindEntry` and `Add`, create simple, hypothetical scenarios with inputs and expected outputs. This helps demonstrate the algorithm's behavior. Assume a small dictionary size for simplicity.

10. **Consider Common Programming Errors:**  Think about common mistakes JavaScript developers make that might relate to the underlying dictionary implementation, even indirectly. Examples include trying to access non-existent properties (leading to `undefined`), adding many properties to an object, and deleting properties.

11. **Structure the Answer:** Organize the information logically, starting with the core function, then diving into details, JavaScript examples, code logic, and potential errors. Use headings and bullet points for clarity. Emphasize the connection between the Torque code and the underlying C++ implementation and JavaScript behavior.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this is just for a specific type of object.
* **Correction:** The name "Swiss *Name* Dictionary" and the usage of `Name` type suggests it's more general, likely used for regular object properties.
* **Initial thought:** The `meta_table` is just for tracking used/free slots.
* **Refinement:**  The different sizes (`kMax1ByteMetaTableCapacity`, `kMax2ByteMetaTableCapacity`) indicate a more complex scheme, possibly optimizing for space depending on the dictionary size.
* **Initial thought:**  The SIMD and portable versions are just minor optimizations.
* **Refinement:** This highlights a significant performance consideration in V8, using vector instructions for faster lookups and insertions when available.

By following these steps, and constantly relating the Torque code back to its purpose and how it's used within V8, we can generate a comprehensive and accurate analysis.
`v8/src/objects/swiss-name-dictionary.tq` 是一个 V8 源代码文件，它定义了名为 `SwissNameDictionary` 的数据结构，用于高效地存储和检索 JavaScript 对象的属性。由于文件以 `.tq` 结尾，可以确定它是一个 **V8 Torque 源代码**。

**功能概述：**

`SwissNameDictionary` 的主要功能是作为一个高性能的哈希表，专门用于存储 JavaScript 对象的属性名称和对应的值（以及其他元数据）。它采用了 **Swiss Table** 这种优化的哈希表算法。

以下是其关键功能点的详细说明：

1. **高效的属性查找:**  `SwissNameDictionary` 旨在快速地根据属性名称（`Name` 类型）找到对应的属性值。它通过 `SwissTableFindEntry` 运行时函数实现高效的查找操作。代码中提供了 SIMD (`SwissNameDictionaryFindEntrySIMD`) 和非 SIMD (`SwissNameDictionaryFindEntryPortable`) 两种实现，以利用硬件加速。

2. **高效的属性添加:**  允许向字典中添加新的属性名称和值。通过 `SwissTableAdd` 运行时函数实现。同样，提供了 SIMD 和非 SIMD 两种添加操作 (`SwissNameDictionaryAddSIMD` 和 `SwissNameDictionaryAddPortable`)。

3. **属性删除:**  支持从字典中删除属性。`SwissNameDictionaryDelete` 宏实现了删除操作，并在删除后检查是否需要收缩字典以节省内存。

4. **动态调整大小:**  `SwissNameDictionary` 可以根据存储的属性数量动态调整其容量。`SwissNameDictionaryCapacityFor` 宏用于计算合适的容量，而 `ShrinkSwissNameDictionary` 运行时函数用于收缩字典。

5. **元数据存储:** 除了键值对外，它还存储与属性相关的元数据，例如属性的详细信息（通过 `property_details_table` 和相关的宏进行操作）。

6. **优化的哈希表实现 (Swiss Table):**  代码中使用了 `ctrl_table` 和分组加载 (`GroupSse2Loader`, `GroupPortableLoader`) 等概念，这些都是 Swiss Table 算法的关键组成部分。Swiss Table 是一种现代化的哈希表实现，旨在提高查找效率并减少冲突。

**与 JavaScript 功能的关系及示例：**

`SwissNameDictionary` 是 V8 引擎内部用于表示 JavaScript 对象的属性存储的核心数据结构之一。每当你创建一个 JavaScript 对象并为其添加属性时，V8 内部很可能就会使用 `SwissNameDictionary` (或者类似的结构，例如当属性较少时可能使用更简单的线性结构) 来存储这些属性。

**JavaScript 示例：**

```javascript
// 创建一个 JavaScript 对象
const myObject = {};

// 添加属性
myObject.name = "Alice";
myObject.age = 30;
myObject.city = "New York";

// 访问属性
console.log(myObject.name); // 输出 "Alice"

// 删除属性
delete myObject.age;

// 尝试访问已删除的属性
console.log(myObject.age); // 输出 undefined
```

在上面的 JavaScript 代码中，当执行 `myObject.name = "Alice"` 等操作时，V8 内部会调用类似于 `SwissTableAdd` 的函数将属性名 "name" 和值 "Alice" 存储到 `myObject` 对应的 `SwissNameDictionary` 中。当执行 `console.log(myObject.name)` 时，V8 会调用类似于 `SwissTableFindEntry` 的函数来查找 "name" 属性对应的值。`delete myObject.age` 操作则会调用类似于 `SwissNameDictionaryDelete` 的函数来移除该属性。

**代码逻辑推理与假设输入输出：**

让我们以 `SwissNameDictionaryFindEntryPortable` 宏为例进行逻辑推理。

**假设输入：**

* `table`: 一个 `SwissNameDictionary` 实例，其中包含一些属性。
* `key`: 一个 `Name` 类型的对象，表示要查找的属性名，例如 "name"。

**内部逻辑推理 (简化版):**

1. 计算 `key` 的哈希值 (`LoadNameHash(key)`).
2. 根据哈希值和字典的容量计算一个起始的探测位置 (`Probe`).
3. 从 `ctrl_table` 中加载一组控制字节 (`GroupPortableLoader{}.LoadGroup`).
4. 将控制字节与 `key` 哈希值的第二部分 (`H2(hash)`) 进行匹配 (`group.Match`).
5. 如果找到匹配的控制字节，则进一步检查 `data_table` 中对应位置的键是否与输入的 `key` 完全相等 (`TaggedEqual(key, candidateKey)`).
6. 如果找到完全匹配的键，则跳转到 `Found` 标签，并携带该条目的索引。
7. 如果当前组中没有匹配，则继续探测下一个位置。
8. 如果探测完所有可能的位置都没有找到，则跳转到 `NotFound` 标签。

**可能的输出：**

* **Found(intptr):** 如果找到键，则输出 `data_table` 中对应条目的索引 (`intptr`)。
* **NotFound:** 如果未找到键，则跳转到 `NotFound` 标签。

**用户常见的编程错误及示例：**

虽然用户通常不会直接与 `SwissNameDictionary` 交互，但了解其背后的原理可以帮助理解一些常见的 JavaScript 编程错误。

1. **访问不存在的属性:**

   ```javascript
   const obj = { name: "Bob" };
   console.log(obj.age); // 输出 undefined
   ```

   在这种情况下，当尝试访问 `obj.age` 时，V8 内部会在 `SwissNameDictionary` 中查找 "age" 属性，但由于该属性不存在，查找操作会返回 "未找到" 的结果，最终 JavaScript 会返回 `undefined`。

2. **过度添加属性导致性能下降 (理论上):**

   虽然 `SwissNameDictionary` 旨在高效处理大量属性，但如果一个对象拥有非常非常多的属性，且这些属性是动态添加的，可能会触发字典的扩容操作，这在某些情况下可能会带来性能开销。当然，V8 的实现会尽可能优化这些操作。

3. **依赖属性的顺序 (在某些旧版本或特殊情况下):**

   虽然现代 JavaScript 对象通常保留属性的插入顺序，但在某些旧版本的 JavaScript 引擎中，或者在处理某些特殊对象（例如，由 C++ 扩展创建的对象）时，属性的枚举顺序可能不是完全可预测的。理解 `SwissNameDictionary` 的哈希表本质有助于理解为什么不应该过度依赖属性的严格顺序。

4. **误解 `delete` 操作的影响:**

   ```javascript
   const obj = { a: 1, b: 2 };
   delete obj.a;
   console.log(obj.a); // 输出 undefined
   ```

   `delete` 操作会实际移除对象的属性。`SwissNameDictionaryDelete` 的作用就是从内部数据结构中移除相应的键值对。理解这一点有助于避免误认为 `delete` 只是将属性值设置为 `undefined` 或 `null`。

**总结：**

`v8/src/objects/swiss-name-dictionary.tq` 定义了 V8 引擎中用于存储 JavaScript 对象属性的关键数据结构 `SwissNameDictionary`。它使用 Swiss Table 算法实现了高效的属性查找、添加和删除操作，并与 JavaScript 对象的属性访问和操作紧密相关。理解其功能有助于深入理解 V8 引擎的内部工作原理以及一些常见的 JavaScript 行为。

Prompt: 
```
这是目录为v8/src/objects/swiss-name-dictionary.tq的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/swiss-name-dictionary.tq以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include 'src/objects/swiss-name-dictionary.h'

@doNotGenerateCppClass
extern class SwissNameDictionary extends HeapObject {
  hash: uint32;
  const capacity: int32;
  meta_table: ByteArray;
  data_table[Convert<intptr>(capacity) * 2]: JSAny|TheHole;
  ctrl_table[Convert<intptr>(capacity) + swiss_table::kGroupWidth]: uint8;
  property_details_table[Convert<intptr>(capacity)]: uint8;
}

namespace swiss_table {

const kDataTableEntryCount: constexpr intptr
    generates 'SwissNameDictionary::kDataTableEntryCount';

const kMax1ByteMetaTableCapacity: constexpr int32
    generates 'SwissNameDictionary::kMax1ByteMetaTableCapacity';

const kMax2ByteMetaTableCapacity: constexpr int32
    generates 'SwissNameDictionary::kMax2ByteMetaTableCapacity';

const kNotFoundSentinel:
    constexpr int32 generates 'SwissNameDictionary::kNotFoundSentinel';

extern macro LoadSwissNameDictionaryKey(SwissNameDictionary, intptr): Name;

extern macro StoreSwissNameDictionaryKeyAndValue(
    SwissNameDictionary, intptr, Object, Object): void;

extern macro SwissNameDictionarySetCtrl(
    SwissNameDictionary, intptr, intptr, uint8): void;

extern macro StoreSwissNameDictionaryPropertyDetails(
    SwissNameDictionary, intptr, intptr, uint8): void;

extern macro SwissNameDictionaryIncreaseElementCountOrBailout(
    ByteArray, intptr, uint32): uint32 labels Bailout;

extern macro StoreSwissNameDictionaryEnumToEntryMapping(
    SwissNameDictionary, intptr, intptr, int32): void;

extern macro SwissNameDictionaryUpdateCountsForDeletion(ByteArray, intptr):
    uint32;

namespace runtime {
extern runtime SwissTableFindEntry(NoContext, SwissNameDictionary, Name): Smi;

extern runtime SwissTableAdd(NoContext, SwissNameDictionary, Name, Object, Smi):
    SwissNameDictionary;

extern runtime ShrinkSwissNameDictionary(NoContext, SwissNameDictionary):
    SwissNameDictionary;
}

// Counterpart for SwissNameDictionary::CapacityFor in C++.
@export
macro SwissNameDictionaryCapacityFor(atLeastSpaceFor: intptr): intptr {
  if (atLeastSpaceFor <= 4) {
    if (atLeastSpaceFor == 0) {
      return 0;
    } else if (atLeastSpaceFor < kSwissNameDictionaryInitialCapacity) {
      return 4;
    } else if (FromConstexpr<bool>(kGroupWidth == 16)) {
      dcheck(atLeastSpaceFor == 4);
      return 4;
    } else if (FromConstexpr<bool>(kGroupWidth == 8)) {
      dcheck(atLeastSpaceFor == 4);
      return 8;
    }
  }

  const nonNormalized = atLeastSpaceFor + atLeastSpaceFor / 7;
  return IntPtrRoundUpToPowerOfTwo32(nonNormalized);
}

// Counterpart for SwissNameDictionary::MaxUsableCapacity in C++.
@export
macro SwissNameDictionaryMaxUsableCapacity(capacity: intptr): intptr {
  dcheck(capacity == 0 || capacity >= kSwissNameDictionaryInitialCapacity);
  if (FromConstexpr<bool>(kGroupWidth == 8) && capacity == 4) {
    // If the group size is 16 we can fully utilize capacity 4: There will be
    // enough kEmpty entries in the ctrl table.
    return 3;
  }
  return capacity - capacity / 8;
}

// Counterpart for SwissNameDictionary::SizeFor in C++.
@export
macro SwissNameDictionarySizeFor(capacity: intptr): intptr {
  const constant: constexpr int32 = kHeapObjectHeaderSize + 8 + kTaggedSize;
  const dynamic: intptr =
      capacity * FromConstexpr<intptr>(2 * kTaggedSize + 2) +
      FromConstexpr<intptr>(kGroupWidth);
  return constant + dynamic;
}

// Counterpart for SwissNameDictionary::MetaTableSizePerEntryFor in C++.
@export
macro SwissNameDictionaryMetaTableSizePerEntryFor(capacity: intptr): intptr {
  if (capacity <= kMax1ByteMetaTableCapacity) {
    return 1;
  } else if (capacity <= kMax2ByteMetaTableCapacity) {
    return 2;
  } else {
    return 4;
  }
}

// Counterpart for SwissNameDictionary::MetaTableSizeFor in C++.
@export
macro SwissNameDictionaryMetaTableSizeFor(capacity: intptr): intptr {
  const perEntry: intptr =
      SwissNameDictionaryMetaTableSizePerEntryFor(capacity);
  const maxUsable: intptr =
      Convert<intptr>(SwissNameDictionaryMaxUsableCapacity(capacity));

  return (2 + maxUsable) * perEntry;
}

//
// Offsets. MT stands for "minus tag"
//

const kDataTableStartOffsetMT: constexpr intptr
    generates 'SwissNameDictionary::DataTableStartOffset() - kHeapObjectTag';

@export
macro SwissNameDictionaryDataTableStartOffsetMT(): intptr {
  return kDataTableStartOffsetMT;
}

@export
macro SwissNameDictionaryCtrlTableStartOffsetMT(capacity: intptr): intptr {
  return kDataTableStartOffsetMT +
      kDataTableEntryCount * FromConstexpr<intptr>(kTaggedSize) * capacity;
}

macro Probe(hash: uint32, mask: uint32): ProbeSequence {
  // Mask must be a power of 2 minus 1.
  dcheck(((mask + 1) & mask) == 0);

  return ProbeSequence{mask: mask, offset: H1(hash) & mask, index: 0};
}

macro FindEntry<GroupLoader: type>(table: SwissNameDictionary, key: Name):
    never labels
Found(intptr), NotFound {
  const hash: uint32 = LoadNameHash(key);
  const capacity: int32 = table.capacity;
  const nonZeroCapacity: int32 = capacity | Convert<int32>(capacity == 0);
  const mask: uint32 = Unsigned(nonZeroCapacity - 1);

  const ctrlTableStart: intptr =
      SwissNameDictionaryCtrlTableStartOffsetMT(Convert<intptr>(capacity)) +
      BitcastTaggedToWord(table);

  let seq = Probe(hash, mask);
  while (true) {
    const group =
        GroupLoader{}.LoadGroup(ctrlTableStart + Convert<intptr>(seq.offset));
    let match = group.Match(H2(hash));
    while (match.HasBitsSet()) {
      const inGroupIndex = match.LowestBitSet();
      const candidateEntry = Convert<intptr>(seq.Offset(inGroupIndex));
      const candidateKey: Object =
          LoadSwissNameDictionaryKey(table, candidateEntry);
      if (TaggedEqual(key, candidateKey)) {
        goto Found(candidateEntry);
      }
      match.ClearLowestSetBit();
    }
    if (group.MatchEmpty().HasBitsSet()) {
      goto NotFound;
    }
    seq.Next();
  }

  unreachable;
}

macro FindFirstEmpty<GroupLoader: type>(
    table: SwissNameDictionary, capacity: intptr, hash: uint32): int32 {
  const nonZeroCapacity: int32 =
      Convert<int32>(capacity) | Convert<int32>(capacity == 0);
  const mask: uint32 = Unsigned(nonZeroCapacity - 1);

  const ctrlTableStart: intptr =
      SwissNameDictionaryCtrlTableStartOffsetMT(capacity) +
      BitcastTaggedToWord(table);

  let seq = Probe(hash, mask);
  while (true) {
    const group =
        GroupLoader{}.LoadGroup(ctrlTableStart + Convert<intptr>(seq.offset));
    const match = group.MatchEmpty();
    if (match.HasBitsSet()) {
      const inGroupIndex = match.LowestBitSet();
      return Signed(seq.Offset(inGroupIndex));
    }
    seq.Next();
  }

  unreachable;
}

macro Add<GroupLoader: type>(
    table: SwissNameDictionary, key: Name, value: Object,
    propertyDetails: uint8): void labels Bailout {
  const capacity: intptr = Convert<intptr>(table.capacity);
  const maxUsable: uint32 =
      Unsigned(Convert<int32>(SwissNameDictionaryMaxUsableCapacity(capacity)));

  try {
    // We read the used capacity (present + deleted elements), compare it
    // against the max usable capacity to determine if a bailout is necessary,
    // and in case of no bailout increase the present element count all in one
    // go using the following macro. This way we don't have to do the branching
    // needed for meta table accesses multiple times.
    const used: uint32 = SwissNameDictionaryIncreaseElementCountOrBailout(
        table.meta_table, capacity, maxUsable) otherwise Bailout;

    const hash: uint32 = LoadNameHash(key);
    const newEntry32 = FindFirstEmpty<GroupLoader>(table, capacity, hash);
    const newEntry = Convert<intptr>(newEntry32);

    StoreSwissNameDictionaryKeyAndValue(table, newEntry, key, value);

    StoreSwissNameDictionaryEnumToEntryMapping(
        table, capacity, Convert<intptr>(used), newEntry32);

    const h2 = Convert<uint8>(Convert<intptr>(H2(hash)));
    SwissNameDictionarySetCtrl(table, capacity, newEntry, h2);

    StoreSwissNameDictionaryPropertyDetails(
        table, capacity, newEntry, propertyDetails);
  } label Bailout {
    goto Bailout;
  }
}

@export
macro SwissNameDictionaryDelete(table: SwissNameDictionary, entry: intptr):
    void labels Shrunk(SwissNameDictionary) {
  const capacity = Convert<intptr>(table.capacity);

  // Update present and deleted element counts at once, without needing to do
  // the meta table access related branching more than once.
  const newElementCount =
      SwissNameDictionaryUpdateCountsForDeletion(table.meta_table, capacity);

  StoreSwissNameDictionaryKeyAndValue(table, entry, TheHole, TheHole);

  const kDeleted = FromConstexpr<uint8>(ctrl::kDeleted);
  SwissNameDictionarySetCtrl(table, capacity, entry, kDeleted);

  // Same logic for deciding when to shrink as in SwissNameDictionary::Delete.
  if (Convert<intptr>(Signed(newElementCount)) < (capacity >> 2)) {
    const shrunkTable = runtime::ShrinkSwissNameDictionary(kNoContext, table);
    goto Shrunk(shrunkTable);
  }
}

// TODO(v8:11330) Ideally, we would like to implement
// CodeStubAssembler::SwissNameDictionaryFindEntry in Torque and do the
// necessary switching between the two implementations with if(kUseSimd) {...}
// else {...}. However, Torque currently generates a call to
// CodeAssembler::Branch which cannot guarantee that code for the "bad" path is
// not generated, even if the branch can be resolved at compile time. This means
// that we end up trying to generate unused code using unsupported instructions.
@export
macro SwissNameDictionaryFindEntrySIMD(
    table: SwissNameDictionary, key: Name): never labels Found(intptr),
    NotFound {
  FindEntry<GroupSse2Loader>(table, key)
      otherwise Found, NotFound;
}

@export
macro SwissNameDictionaryFindEntryPortable(
    table: SwissNameDictionary, key: Name): never labels Found(intptr),
    NotFound {
  FindEntry<GroupPortableLoader>(table, key)
      otherwise Found, NotFound;
}

// TODO(v8:11330) Ideally, we would like to implement
// CodeStubAssembler::SwissNameDictionaryAdd in Torque and do the necessary
// switching between the two implementations with if(kUseSimd) {...} else {...}.
// However, Torque currently generates a call to CodeAssembler::Branch which
// cannot guarantee that code for the "bad" path is not generated, even if the
// branch can be resolved at compile time. This means that we end up trying to
// generate unused code using unsupported instructions.
@export
macro SwissNameDictionaryAddSIMD(
    table: SwissNameDictionary, key: Name, value: Object,
    propertyDetails: uint8): void labels Bailout {
  Add<GroupSse2Loader>(table, key, value, propertyDetails)
      otherwise Bailout;
}

@export
macro SwissNameDictionaryAddPortable(
    table: SwissNameDictionary, key: Name, value: Object,
    propertyDetails: uint8): void labels Bailout {
  Add<GroupPortableLoader>(table, key, value, propertyDetails)
      otherwise Bailout;
}
}

"""

```