Response:
Let's break down the thought process for analyzing the `map.h` header file.

**1. Initial Scan and Obvious Information:**

* **File Name and Location:** The file is `v8/src/objects/map.h`. This immediately tells us it's related to object structures and specifically "maps" within the V8 engine. The `.h` extension signifies a header file in C++.
* **Copyright Notice:**  Standard copyright and license information. Indicates this is part of the V8 project.
* **Include Guards:** `#ifndef V8_OBJECTS_MAP_H_`, `#define V8_OBJECTS_MAP_H_`, `#endif` are standard C++ include guards to prevent multiple inclusions.
* **Includes:**  The `#include` directives give a high-level overview of dependencies. We see includes for:
    * `<optional>`:  C++ standard library for optional values.
    * `"include/v8-memory-span.h"`: V8 specific for memory spans.
    * `"src/base/bit-field.h"`:  Likely for managing bit fields within structures.
    * `"src/common/globals.h"`:  Global V8 definitions.
    * `"src/objects/code.h"`, `"src/objects/fixed-array.h"`, etc.: Other V8 object headers, indicating relationships between different object types.
    * `"src/roots/roots.h"`: Access to the "roots" of the V8 heap.
    * `"torque-generated/bit-fields.h"`, `"torque-generated/visitor-lists.h"`, `"torque-generated/src/objects/map-tq.inc"`:  Crucially, these indicate the use of Torque, V8's internal language for generating code, especially for object layout and訪問. The `.tq` suffix mentioned in the prompt is relevant here, though the file itself is `.h`.
    * `"src/objects/object-macros.h"`: Likely contains helpful macros for defining V8 objects.

**2. Identifying Key Data Structures and Enums:**

* **`enum InstanceType`:**  This strongly suggests that `Map` is related to classifying different types of JavaScript objects.
* **`DATA_ONLY_VISITOR_ID_LIST` and `POINTER_VISITOR_ID_LIST`:**  These macros define lists of different object types. The names "data only" and "pointer" suggest how these objects are treated during garbage collection (whether they contain pointers to other objects).
* **`enum VisitorId`:**  This enum seems to combine the previous lists and adds `TORQUE_VISITOR_ID_LIST` and `TRUSTED_VISITOR_ID_LIST`. This reinforces the importance of Torque in defining object handling. The comment about objects with the same visitor ID being processed the same way during heap visits is a crucial insight into garbage collection.
* **`enum class ObjectFields`:** A simple enum likely used internally to distinguish between different kinds of fields.
* **`using MapHandles` and `using MapHandlesSpan`:** Type aliases related to managing collections of `Map` objects.

**3. Analyzing the `Map` Class Definition:**

* **Inheritance:** `class Map : public TorqueGeneratedMap<Map, HeapObject>`. This confirms that `Map` is a C++ class and inherits from a Torque-generated base class, further emphasizing Torque's role. It also inherits from `HeapObject`, making it a fundamental type on the V8 heap.
* **Comments Describing `Map`:** The extensive comment block explaining the `Map` layout is extremely valuable. It details the structure of a `Map` object in memory, including the purpose of each field (e.g., `instance_size`, `instance_type`, `bit_field`, `prototype`, `constructor_or_back_pointer`, `instance_descriptors`, etc.). This is the core information for understanding the role of `Map`.
* **`DECL_*_ACCESSORS` Macros:**  These macros are heavily used throughout the `Map` class. They are likely defined in `src/objects/object-macros.h` and generate boilerplate code for accessing and setting fields within the `Map` object. The different prefixes (`DECL_INT_ACCESSORS`, `DECL_PRIMITIVE_ACCESSORS`, `DECL_BOOLEAN_ACCESSORS`, `DECL_ACCESSORS`, `DECL_RELAXED_ACCESSORS`, `DECL_RELEASE_ACQUIRE_ACCESSORS`, `DECL_GETTER`) indicate different access patterns and potential concurrency considerations. "Relaxed" and "release_acquire" suggest synchronization mechanisms.
* **Specific Methods:**  Beyond the basic accessors, there are methods with more specific functionality, such as:
    * `GetInObjectPropertiesStartInWords()`, `SetInObjectPropertiesStartInWords()`: Managing in-object properties.
    * `GetConstructorFunction()`, `SetConstructorFunctionIndex()`:  Relating to object constructors.
    * `UsedInstanceSize()`, `UnusedPropertyFields()`: Managing memory usage and optimization.
    * Methods related to bit fields (`Bits1`, `Bits2`, `Bits3`): Providing structured access to the bit flags within the `Map`.
    * `StartInobjectSlackTracking()`, `IsInobjectSlackTrackingInProgress()`, `InobjectSlackTrackingStep()`:  Optimization related to in-object property allocation.
    * `ElementsTransitionMap()`:  Handling transitions between different kinds of array elements.
    * `Normalize()`:  A crucial method for changing the structure of objects.
    * Methods related to prototypes (`GetOrCreatePrototypeInfo`, `GetOrCreatePrototypeChainValidityCell`, `SetPrototype`).
    * Methods for accessing and manipulating descriptors (`GetInstanceDescriptors`, `SetInstanceDescriptors`).
    * Methods related to dependent code.
* **Static Assertions:** `static_assert` statements are used for compile-time checks of constants and bit field sizes, ensuring consistency.

**4. Connecting to JavaScript Functionality:**

* The presence of fields like `prototype`, `constructor_or_back_pointer`, `instance_descriptors`, and methods like `Normalize` strongly link `Map` to the core concepts of JavaScript objects: prototypes, inheritance, properties, and dynamic object structure.
* The various `ElementsKind` related methods (e.g., `has_fast_smi_elements()`, `has_dictionary_elements()`) directly relate to how JavaScript arrays are implemented and optimized.
* The comments mentioning ES6 sections (7.2.3, 7.2.4) explicitly tie `Map` to JavaScript language specifications.

**5. Identifying Potential Programming Errors:**

* While the header file itself doesn't contain executable code, understanding the structure and purpose of `Map` helps in diagnosing errors related to object structure, property access, and prototype chains in JavaScript. For example, understanding how transitions work is crucial for performance debugging.

**6. Focusing on the Request's Specific Points:**

* **Functionality Listing:**  Systematically go through the class members (fields and methods) and describe their purpose based on their names, types, and comments.
* **Torque:** Recognize the `.tq` implication and highlight the use of Torque-generated code.
* **JavaScript Relationship:**  Connect the `Map`'s features to corresponding JavaScript concepts (prototypes, properties, etc.) and provide JavaScript examples to illustrate.
* **Code Logic (Inference):**  Identify methods that perform some kind of logic (e.g., `ComputeMinObjectSlack`) and try to infer their input and output based on their names and context.
* **Common Programming Errors:**  Think about how misunderstandings about object structure and prototypes could lead to errors (e.g., modifying prototypes, adding properties dynamically).
* **Summarization (Part 1):** Condense the key functionalities into a concise summary.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just a C++ header file."  **Correction:** Recognize the heavy reliance on Torque, which significantly influences the structure and generation of the code.
* **Initial thought:** "The `Map` is just a simple data structure." **Correction:**  Realize the complexity and crucial role of `Map` in the V8 engine, impacting performance, garbage collection, and JavaScript semantics.
* **Initial thought:** "The `DECL_*_ACCESSORS` macros are just for getters and setters." **Correction:** Understand that they might involve more complex logic, including memory management and synchronization.
* **Over-reliance on code details:** **Correction:**  Balance the analysis of code details with the high-level purpose and connection to JavaScript. Focus on the "what" and "why" rather than just the "how."

By following this kind of systematic analysis, combining code inspection with domain knowledge of JavaScript and the V8 engine, it's possible to generate a comprehensive understanding of the `map.h` file's purpose and functionality.
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_MAP_H_
#define V8_OBJECTS_MAP_H_

#include <optional>

#include "include/v8-memory-span.h"
#include "src/base/bit-field.h"
#include "src/common/globals.h"
#include "src/objects/code.h"
#include "src/objects/fixed-array.h"
#include "src/objects/heap-object.h"
#include "src/objects/instance-type-checker.h"
#include "src/objects/internal-index.h"
#include "src/objects/objects.h"
#include "src/objects/prototype-info.h"
#include "src/roots/roots.h"
#include "torque-generated/bit-fields.h"
#include "torque-generated/visitor-lists.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8::internal {

class WasmTypeInfo;

enum InstanceType : uint16_t;

#define DATA_ONLY_VISITOR_ID_LIST(V) \
  V(BigInt)                          \
  V(CoverageInfo)                    \
  V(FeedbackMetadata)                \
  V(Filler)                          \
  V(HeapNumber)                      \
  V(SeqOneByteString)                \
  V(SeqTwoByteString)                \
  IF_WASM(V, WasmNull)

#define POINTER_VISITOR_ID_LIST(V)   \
  V(AccessorInfo)                    \
  V(AllocationSite)                  \
  V(BytecodeWrapper)                 \
  V(CallSiteInfo)                    \
  V(Cell)                            \
  V(CodeWrapper)                     \
  V(ConsString)                      \
  V(ContextSidePropertyCell)         \
  V(DataHandler)                     \
  V(DebugInfo)                       \
  V(EmbedderDataArray)               \
  V(EphemeronHashTable)              \
  V(ExternalString)                  \
  V(FeedbackCell)                    \
  V(Foreign)                         \
  V(FreeSpace)                       \
  V(FunctionTemplateInfo)            \
  V(Hole)                            \
  V(JSApiObject)                     \
  V(JSArrayBuffer)                   \
  V(JSDataViewOrRabGsabDataView)     \
  V(JSDate)                          \
  V(JSExternalObject)                \
  V(JSFinalizationRegistry)          \
  V(JSFunction)                      \
  V(JSObject)                        \
  V(JSObjectFast)                    \
  V(JSRegExp)                        \
  V(JSSynchronizationPrimitive)      \
  V(JSTypedArray)                    \
  V(JSWeakCollection)                \
  V(JSWeakRef)                       \
  V(Map)                             \
  V(NativeContext)                   \
  V(Oddball)                         \
  V(PreparseData)                    \
  V(PropertyArray)                   \
  V(PropertyCell)                    \
  V(PrototypeInfo)                   \
  V(RegExpBoilerplateDescription)    \
  V(RegExpDataWrapper)               \
  V(SharedFunctionInfo)              \
  V(ShortcutCandidate)               \
  V(SlicedString)                    \
  V(SloppyArgumentsElements)         \
  V(SmallOrderedHashMap)             \
  V(SmallOrderedHashSet)             \
  V(SmallOrderedNameDictionary)      \
  V(SourceTextModule)                \
  V(Struct)                          \
  V(SwissNameDictionary)             \
  V(Symbol)                          \
  V(SyntheticModule)                 \
  V(ThinString)                      \
  V(TransitionArray)                 \
  IF_WASM(V, WasmArray)              \
  IF_WASM(V, WasmContinuationObject) \
  IF_WASM(V, WasmFuncRef)            \
  IF_WASM(V, WasmGlobalObject)       \
  IF_WASM(V, WasmInstanceObject)     \
  IF_WASM(V, WasmMemoryObject)       \
  IF_WASM(V, WasmResumeData)         \
  IF_WASM(V, WasmStruct)             \
  IF_WASM(V, WasmSuspenderObject)    \
  IF_WASM(V, WasmSuspendingObject)   \
  IF_WASM(V, WasmTableObject)        \
  IF_WASM(V, WasmTagObject)          \
  IF_WASM(V, WasmTypeInfo)           \
  V(WeakCell)                        \
  SIMPLE_HEAP_OBJECT_LIST1(V)

#define TORQUE_VISITOR_ID_LIST(V)     \
  TORQUE_DATA_ONLY_VISITOR_ID_LIST(V) \
  TORQUE_POINTER_VISITOR_ID_LIST(V)

#define TRUSTED_VISITOR_ID_LIST(V) CONCRETE_TRUSTED_OBJECT_TYPE_LIST1(V)

// Objects with the same visitor id are processed in the same way by
// the heap visitors. The visitor ids for data only objects must precede
// other visitor ids. We rely on kDataOnlyVisitorIdCount for quick check
// of whether an object contains only data or may contain pointers.
enum VisitorId {
#define VISITOR_ID_ENUM_DECL(id) kVisit##id,
  // clang-format off
  DATA_ONLY_VISITOR_ID_LIST(VISITOR_ID_ENUM_DECL)
  TORQUE_DATA_ONLY_VISITOR_ID_LIST(VISITOR_ID_ENUM_DECL)
  kDataOnlyVisitorIdCount,
  POINTER_VISITOR_ID_LIST(VISITOR_ID_ENUM_DECL)
  TORQUE_POINTER_VISITOR_ID_LIST(VISITOR_ID_ENUM_DECL)
  TRUSTED_VISITOR_ID_LIST(VISITOR_ID_ENUM_DECL)
  kVisitorIdCount
// clang-format on
#undef VISITOR_ID_ENUM_DECL
};

enum class ObjectFields {
  kDataOnly,
  kMaybePointers,
};

using MapHandles = std::vector<Handle<Map>>;
using MapHandlesSpan = v8::MemorySpan<Handle<Map>>;

#include "torque-generated/src/objects/map-tq.inc"

// All heap objects have a Map that describes their structure.
//  A Map contains information about:
//  - Size information about the object
//  - How to iterate over an object (for garbage collection)
//
// Map layout:
// +---------------+-------------------------------------------------+
// |   _ Type _    | _ Description _                                 |
// +---------------+-------------------------------------------------+
// | TaggedPointer | map - Always a pointer to the MetaMap root      |
// +---------------+-------------------------------------------------+
// | Int           | The first int field                             |
//  `---+----------+-------------------------------------------------+
//      | Byte     | [instance_size]                                 |
//      +----------+-------------------------------------------------+
//      | Byte     | If Map for a primitive type:                    |
//      |          |   native context index for constructor fn       |
//      |          | If Map for an Object type:                      |
//      |          |   inobject properties start offset in words     |
//      +----------+-------------------------------------------------+
//      | Byte     | [used_or_unused_instance_size_in_words]         |
//      |          | For JSObject in fast mode this byte encodes     |
//      |          | the size of the object that includes only       |
//      |          | the used property fields or the slack size      |
//      |          | in properties backing store.                    |
//      +----------+-------------------------------------------------+
//      | Byte     | [visitor_id]                                    |
// +----+----------+-------------------------------------------------+
// | Int           | The second int field                            |
//  `---+----------+-------------------------------------------------+
//      | Short    | [instance_type]                                 |
//      +----------+-------------------------------------------------+
//      | Byte     | [bit_field]                                     |
//      |          |   - has_non_instance_prototype (bit 0)          |
//      |          |   - is_callable (bit 1)                         |
//      |          |   - has_named_interceptor (bit 2)               |
//      |          |   - has_indexed_interceptor (bit 3)             |
//      |          |   - is_undetectable (bit 4)                     |
//      |          |   - is_access_check_needed (bit 5)              |
//      |          |   - is_constructor (bit 6)                      |
//      |          |   - has_prototype_slot (bit 7)                  |
//      +----------+-------------------------------------------------+
//      | Byte     | [bit_field2]                                    |
//      |          |   - new_target_is_base (bit 0)                  |
//      |          |   - is_immutable_proto (bit 1)                  |
//      |          |   - elements_kind (bits 2..7)                   |
// +----+----------+-------------------------------------------------+
// | Int           | [bit_field3]                                    |
// |               |   - enum_length (bit 0..9)                      |
// |               |   - number_of_own_descriptors (bit 10..19)      |
// |               |   - is_prototype_map (bit 20)                   |
// |               |   - is_dictionary_map (bit 21)                  |
// |               |   - owns_descriptors (bit 22)                   |
// |               |   - is_in_retained_map_list (bit 23)            |
// |               |   - is_deprecated (bit 24)                      |
// |               |   - is_unstable (bit 25)                        |
// |               |   - is_migration_target (bit 26)                |
// |               |   - is_extensible (bit 28)                      |
// |               |   - may_have_interesting_properties (bit 28)    |
// |               |   - construction_counter (bit 29..31)           |
// |               |                                                 |
// +*****************************************************************+
// | Int           | On systems with 64bit pointer types, there      |
// |               | is an unused 32bits after bit_field3            |
// +*****************************************************************+
// | TaggedPointer | [prototype]                                     |
// +---------------+-------------------------------------------------+
// | TaggedPointer | [constructor_or_back_pointer_or_native_context] |
// +---------------+-------------------------------------------------+
// | TaggedPointer | [instance_descriptors]                          |
// +*****************************************************************+
// | TaggedPointer | [dependent_code]                                |
// +---------------+-------------------------------------------------+
// | TaggedPointer | [prototype_validity_cell]                       |
// +---------------+-------------------------------------------------+
// | TaggedPointer | If Map is a prototype map:                      |
// |               |   [prototype_info]                              |
// |               | Else:                                           |
// |               |   [raw_transitions]                             |
// +---------------+-------------------------------------------------+

class Map : public TorqueGeneratedMap<Map, HeapObject> {
 public:
  // Instance size.
  // Size in bytes or kVariableSizeSentinel if instances do not have
  // a fixed size.
  DECL_INT_ACCESSORS(instance_size)
  // Size in words or kVariableSizeSentinel if instances do not have
  // a fixed size.
  DECL_INT_ACCESSORS(instance_size_in_words)

  // [inobject_properties_start_or_constructor_function_index]:
  // Provides access to the inobject properties start offset in words in case of
  // JSObject maps, or the constructor function index in case of primitive maps.
  DECL_INT_ACCESSORS(inobject_properties_start_or_constructor_function_index)

  // Get/set the in-object property area start offset in words in the object.
  inline int GetInObjectPropertiesStartInWords() const;
  inline void SetInObjectPropertiesStartInWords(int value);
  // Count of properties allocated in the object (JSObject only).
  inline int GetInObjectProperties() const;
  // Index of the constructor function in the native context (primitives only),
  // or the special sentinel value to indicate that there is no object wrapper
  // for the primitive (i.e. in case of null or undefined).
  static const int kNoConstructorFunctionIndex = 0;
  inline int GetConstructorFunctionIndex() const;
  inline void SetConstructorFunctionIndex(int value);
  static std::optional<Tagged<JSFunction>> GetConstructorFunction(
      Tagged<Map> map, Tagged<Context> native_context);

  // Retrieve interceptors.
  DECL_GETTER(GetNamedInterceptor, Tagged<InterceptorInfo>)
  DECL_GETTER(GetIndexedInterceptor, Tagged<InterceptorInfo>)

  // Instance type.
  DECL_PRIMITIVE_ACCESSORS(instance_type, InstanceType)

  // Returns the size of the used in-object area including object header
  // (only used for JSObject in fast mode, for the other kinds of objects it
  // is equal to the instance size).
  inline int UsedInstanceSize() const;

  inline bool HasOutOfObjectProperties() const;

  // Tells how many unused property fields (in-object or out-of object) are
  // available in the instance (only used for JSObject in fast mode).
  inline int UnusedPropertyFields() const;
  // Tells how many unused in-object property words are present.
  inline int UnusedInObjectProperties() const;
  // Updates the counters tracking unused fields in the object.
  inline void SetInObjectUnusedPropertyFields(int unused_property_fields);
  // Updates the counters tracking unused fields in the property array.
  inline void SetOutOfObjectUnusedPropertyFields(int unused_property_fields);
  inline void CopyUnusedPropertyFields(Tagged<Map> map);
  inline void CopyUnusedPropertyFieldsAdjustedForInstanceSize(Tagged<Map> map);
  inline void AccountAddedPropertyField();
  inline void AccountAddedOutOfObjectPropertyField(
      int unused_in_property_array);

  //
  // Bit field.
  //
  // The setter in this pair calls the relaxed setter if concurrent marking is
  // on, or performs the write non-atomically if it's off. The read is always
  // non-atomically. This is done to have wider TSAN coverage on the cases where
  // it's possible.
  DECL_PRIMITIVE_ACCESSORS(bit_field, uint8_t)

  // Atomic accessors, used for allowlisting legitimate concurrent accesses.
  DECL_PRIMITIVE_ACCESSORS(relaxed_bit_field, uint8_t)

  // Bit positions for |bit_field|.
  struct Bits1 {
    DEFINE_TORQUE_GENERATED_MAP_BIT_FIELDS1()
  };

  //
  // Bit field 2.
  //
  DECL_PRIMITIVE_ACCESSORS(bit_field2, uint8_t)

  // Bit positions for |bit_field2|.
  struct Bits2 {
    DEFINE_TORQUE_GENERATED_MAP_BIT_FIELDS2()
  };

  //
  // Bit field 3.
  //
  // {bit_field3} calls the relaxed accessors if concurrent marking is on, or
  // performs the read/write non-atomically if it's off. This is done to have
  // wider TSAN coverage on the cases where it's possible.
  DECL_PRIMITIVE_ACCESSORS(bit_field3, uint32_t)

  DECL_PRIMITIVE_ACCESSORS(relaxed_bit_field3, uint32_t)
  DECL_PRIMITIVE_ACCESSORS(release_acquire_bit_field3, uint32_t)

  // Clear uninitialized padding space. This ensures that the snapshot content
  // is deterministic. Depending on the V8 build mode there could be no padding.
  V8_INLINE void clear_padding();

  // Bit positions for |bit_field3|.
  struct Bits3 {
    DEFINE_TORQUE_GENERATED_MAP_BIT_FIELDS3()
  };

  // Ensure that Torque-defined bit widths for |bit_field3| are as expected.
  static_assert(Bits3::EnumLengthBits::kSize == kDescriptorIndexBitCount);
  static_assert(Bits3::NumberOfOwnDescriptorsBits::kSize ==
                kDescriptorIndexBitCount);

  static_assert(Bits3::NumberOfOwnDescriptorsBits::kMax >=
                kMaxNumberOfDescriptors);

  static const int kSlackTrackingCounterStart = 7;
  static const int kSlackTrackingCounterEnd = 1;
  static const int kNoSlackTracking = 0;
  static_assert(kSlackTrackingCounterStart <=
                Bits3::ConstructionCounterBits::kMax);

  // Inobject slack tracking is the way to reclaim unused inobject space.
  //
  // The instance size is initially determined by adding some slack to
  // expected_nof_properties (to allow for a few extra properties added
  // after the constructor). There is no guarantee that the extra space
  // will not be wasted.
  //
  // Here is the algorithm to reclaim the unused inobject space:
  // - Detect the first constructor call for this JSFunction.
  //   When it happens enter the "in progress" state: initialize construction
  //   counter in the initial_map.
  // - While the tracking is in progress initialize unused properties of a new
  //   object with one_pointer_filler_map instead of undefined_value (the "used"
  //   part is initialized with undefined_value as usual). This way they can
  //   be resized quickly and safely.
  // - Once enough objects have been created  compute the 'slack'
  //   (traverse the map transition tree starting from the
  //   initial_map and find the lowest value of unused_property_fields).
  // - Traverse the transition tree again and decrease the instance size
  //   of every map. Existing objects will resize automatically (they are
  //   filled with one_pointer_filler_map). All further allocations will
  //   use the adjusted instance size.
  // - SharedFunctionInfo's expected_nof_properties left unmodified since
  //   allocations made using different closures could actually create different
  //   kind of objects (see prototype inheritance pattern).
  //
  //  Important: inobject slack tracking is not attempted during the snapshot
  //  creation.

  static const int kGenerousAllocationCount =
      kSlackTrackingCounterStart - kSlackTrackingCounterEnd + 1;

  // Starts the tracking by initializing object constructions countdown counter.
  void StartInobjectSlackTracking();

  // True if the object constructions countdown counter is a range
  // [kSlackTrackingCounterEnd, kSlackTrackingCounterStart].
  inline bool IsInobjectSlackTrackingInProgress() const;

  // Does the tracking step.
  inline void InobjectSlackTrackingStep(Isolate* isolate);

  // Computes inobject slack for the transition tree starting at this initial
  // map.
  int ComputeMinObjectSlack(Isolate* isolate);
  inline int InstanceSizeFromSlack(int slack) const;

  // Tells whether the object in the prototype property will be used
  // for instances created from this function. If the prototype
  // property is set to a value that is not a JSObject, the prototype
  // property will not be used to create instances of the function.
  // See ECMA-262, 13.2.2.
  DECL_BOOLEAN_ACCESSORS(has_non_instance_prototype)

  // Tells whether the instance has a [[Construct]] internal method.
  // This property is implemented according to ES6, section 7.2.4.
  DECL_BOOLEAN_ACCESSORS(is_constructor)

  // Tells whether the instance with this map may have properties for
  // interesting symbols on it.
  // An "interesting symbol" is one for which Name::IsInteresting()
  // returns true, i.e. a well-known symbol like @@toStringTag.
  DECL_BOOLEAN_ACCESSORS(may_have_interesting_properties)

  DECL_BOOLEAN_ACCESSORS(has_prototype_slot)

  // Records and queries whether the instance has a named interceptor.
  DECL_BOOLEAN_ACCESSORS(has_named_interceptor)

  // Records and queries whether the instance has an indexed interceptor.
  DECL_BOOLEAN_ACCESSORS(has_indexed_interceptor)

  // Tells whether the instance is undetectable.
  // An undetectable object is a special class of JSObject: 'typeof' operator
  // returns undefined, ToBoolean returns false. Otherwise it behaves like
  // a normal JS object. It is useful for implementing undetectable
  // document.all in Firefox & Safari.
  // See https://bugzilla.mozilla.org/show_bug.cgi?id=248549.
  DECL_BOOLEAN_ACCESSORS(is_undetectable)

  // Tells whether the instance has a [[Call]] internal method.
  // This property is implemented according to ES6, section 7.2.3.
  DECL_BOOLEAN_ACCESSORS(is_callable)

  DECL_BOOLEAN_ACCESSORS(new_target_is_base)
  DECL_BOOLEAN_ACCESSORS(is_extensible)
  DECL_BOOLEAN_ACCESSORS(is_prototype_map)
  inline bool is_abandoned_prototype_map() const;
  inline bool has_prototype_info() const;
  inline bool TryGetPrototypeInfo(Tagged<PrototypeInfo>* result) const;

  // Whether the instance has been added to the retained map list by
  // Heap::AddRetainedMap.
  DECL_BOOLEAN_ACCESSORS(is_in_retained_map_list)

  DECL_PRIMITIVE_ACCESSORS(elements_kind, ElementsKind)

  // Tells whether the instance has fast elements that are only Smis.
  inline bool has_fast_smi_elements() const;

  // Tells whether the instance has fast elements.
  inline bool has_fast_object_elements() const;
  inline bool has_fast_smi_or_object_elements() const;
  inline bool has_fast_double_elements() const;
  inline bool has_fast_elements() const;
  inline bool has_fast_packed_elements() const;
  inline bool has_sloppy_arguments_elements() const;
  inline bool has_fast_sloppy_arguments_elements() const;
  inline bool has_fast_string_wrapper_elements() const;
  inline bool has_typed_array_or_rab_gsab_typed_array_elements() const;
  inline bool has_any_typed_array_or_wasm_array_elements() const;
  inline bool has_dictionary_elements() const;
  inline bool has_any_nonextensible_elements() const;
  inline bool has_nonextensible_elements() const;
  inline bool has_sealed_elements() const;
  inline bool has_frozen_elements() const;
  inline bool has_shared_array_elements() const;

  // Weakly checks whether a map is detached from all transition trees. If this
  // returns true, the map is guaranteed to be detached. If it returns false,
  // there is no guarantee it is attached.
  inline bool IsDetached(Isolate* isolate) const;

  // Returns true if there is an object with potentially read-only elements
  // in the prototype chain. It could be a Proxy, a string wrapper,
  // an object with DICTIONARY_ELEMENTS potentially containing read-only
  // elements or an object with any frozen elements, or a slow arguments object.
  bool ShouldCheckForReadOnlyElementsInPrototypeChain(Isolate* isolate);

  inline Tagged<Map> ElementsTransitionMap(Isolate* isolate,
                                           ConcurrencyMode cmode);

  inline Tagged<FixedArrayBase> GetInitialElements() const;

  // [raw_transitions]: Provides access to the transitions storage field.
  // Don't call set_raw_transitions() directly to overwrite transitions, use
  // the TransitionArray::ReplaceTransitions() wrapper instead!
  DECL_ACCESSORS(raw_transitions,
                 Tagged<UnionOf<Smi, MaybeWeak<Map>, TransitionArray>>)
  DECL_RELEASE_ACQUIRE_ACCESSORS(
      raw_transitions, Tagged<UnionOf<Smi, MaybeWeak<Map>, TransitionArray>>)
  // [prototype_info]: Per-prototype metadata. Aliased with transitions
  // (which prototype maps don't have).
  DECL_GETTER(prototype_info, Tagged<UnionOf<Smi, PrototypeInfo>>)
  DECL_RELEASE_ACQUIRE_ACCESSORS(prototype_info,
                                 Tagged<UnionOf<Smi, PrototypeInfo>>)
  // PrototypeInfo is created lazily using this helper (which installs it on
  // the given prototype's map).
  static Handle<PrototypeInfo> GetOrCreatePrototypeInfo(
      DirectHandle<JSObject> prototype, Isolate* isolate);
  static Handle<PrototypeInfo> GetOrCreatePrototypeInfo(
      DirectHandle<Map> prototype_map, Isolate* isolate);
  inline bool should_be_fast_prototype_map() const;
  static void SetShouldBeFastPrototypeMap(DirectHandle<Map> map, bool value,
                                          Isolate* isolate);

  // [prototype chain validity cell]: Associated with a prototype object,
  // stored in that object's map, indicates that prototype chains through this
  // object are currently valid. The cell will be invalidated and replaced when
  // the prototype chain changes. When there's nothing to guard (for example,
  // when direct prototype is null or Proxy) this function returns Smi with
  // |kPrototypeChainValid| sentinel value, which is zero.
  static Handle<UnionOf<Smi, Cell>> GetOrCreatePrototypeChainValidityCell(
      DirectHandle<Map> map, Isolate* isolate);
  static constexpr int kPrototypeChainValid = 0;
  static constexpr int kPrototypeChainInvalid = 1;
  static constexpr Tag
### 提示词
```
这是目录为v8/src/objects/map.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/map.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_MAP_H_
#define V8_OBJECTS_MAP_H_

#include <optional>

#include "include/v8-memory-span.h"
#include "src/base/bit-field.h"
#include "src/common/globals.h"
#include "src/objects/code.h"
#include "src/objects/fixed-array.h"
#include "src/objects/heap-object.h"
#include "src/objects/instance-type-checker.h"
#include "src/objects/internal-index.h"
#include "src/objects/objects.h"
#include "src/objects/prototype-info.h"
#include "src/roots/roots.h"
#include "torque-generated/bit-fields.h"
#include "torque-generated/visitor-lists.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8::internal {

class WasmTypeInfo;

enum InstanceType : uint16_t;

#define DATA_ONLY_VISITOR_ID_LIST(V) \
  V(BigInt)                          \
  V(CoverageInfo)                    \
  V(FeedbackMetadata)                \
  V(Filler)                          \
  V(HeapNumber)                      \
  V(SeqOneByteString)                \
  V(SeqTwoByteString)                \
  IF_WASM(V, WasmNull)

#define POINTER_VISITOR_ID_LIST(V)   \
  V(AccessorInfo)                    \
  V(AllocationSite)                  \
  V(BytecodeWrapper)                 \
  V(CallSiteInfo)                    \
  V(Cell)                            \
  V(CodeWrapper)                     \
  V(ConsString)                      \
  V(ContextSidePropertyCell)         \
  V(DataHandler)                     \
  V(DebugInfo)                       \
  V(EmbedderDataArray)               \
  V(EphemeronHashTable)              \
  V(ExternalString)                  \
  V(FeedbackCell)                    \
  V(Foreign)                         \
  V(FreeSpace)                       \
  V(FunctionTemplateInfo)            \
  V(Hole)                            \
  V(JSApiObject)                     \
  V(JSArrayBuffer)                   \
  V(JSDataViewOrRabGsabDataView)     \
  V(JSDate)                          \
  V(JSExternalObject)                \
  V(JSFinalizationRegistry)          \
  V(JSFunction)                      \
  V(JSObject)                        \
  V(JSObjectFast)                    \
  V(JSRegExp)                        \
  V(JSSynchronizationPrimitive)      \
  V(JSTypedArray)                    \
  V(JSWeakCollection)                \
  V(JSWeakRef)                       \
  V(Map)                             \
  V(NativeContext)                   \
  V(Oddball)                         \
  V(PreparseData)                    \
  V(PropertyArray)                   \
  V(PropertyCell)                    \
  V(PrototypeInfo)                   \
  V(RegExpBoilerplateDescription)    \
  V(RegExpDataWrapper)               \
  V(SharedFunctionInfo)              \
  V(ShortcutCandidate)               \
  V(SlicedString)                    \
  V(SloppyArgumentsElements)         \
  V(SmallOrderedHashMap)             \
  V(SmallOrderedHashSet)             \
  V(SmallOrderedNameDictionary)      \
  V(SourceTextModule)                \
  V(Struct)                          \
  V(SwissNameDictionary)             \
  V(Symbol)                          \
  V(SyntheticModule)                 \
  V(ThinString)                      \
  V(TransitionArray)                 \
  IF_WASM(V, WasmArray)              \
  IF_WASM(V, WasmContinuationObject) \
  IF_WASM(V, WasmFuncRef)            \
  IF_WASM(V, WasmGlobalObject)       \
  IF_WASM(V, WasmInstanceObject)     \
  IF_WASM(V, WasmMemoryObject)       \
  IF_WASM(V, WasmResumeData)         \
  IF_WASM(V, WasmStruct)             \
  IF_WASM(V, WasmSuspenderObject)    \
  IF_WASM(V, WasmSuspendingObject)   \
  IF_WASM(V, WasmTableObject)        \
  IF_WASM(V, WasmTagObject)          \
  IF_WASM(V, WasmTypeInfo)           \
  V(WeakCell)                        \
  SIMPLE_HEAP_OBJECT_LIST1(V)

#define TORQUE_VISITOR_ID_LIST(V)     \
  TORQUE_DATA_ONLY_VISITOR_ID_LIST(V) \
  TORQUE_POINTER_VISITOR_ID_LIST(V)

#define TRUSTED_VISITOR_ID_LIST(V) CONCRETE_TRUSTED_OBJECT_TYPE_LIST1(V)

// Objects with the same visitor id are processed in the same way by
// the heap visitors. The visitor ids for data only objects must precede
// other visitor ids. We rely on kDataOnlyVisitorIdCount for quick check
// of whether an object contains only data or may contain pointers.
enum VisitorId {
#define VISITOR_ID_ENUM_DECL(id) kVisit##id,
  // clang-format off
  DATA_ONLY_VISITOR_ID_LIST(VISITOR_ID_ENUM_DECL)
  TORQUE_DATA_ONLY_VISITOR_ID_LIST(VISITOR_ID_ENUM_DECL)
  kDataOnlyVisitorIdCount,
  POINTER_VISITOR_ID_LIST(VISITOR_ID_ENUM_DECL)
  TORQUE_POINTER_VISITOR_ID_LIST(VISITOR_ID_ENUM_DECL)
  TRUSTED_VISITOR_ID_LIST(VISITOR_ID_ENUM_DECL)
  kVisitorIdCount
// clang-format on
#undef VISITOR_ID_ENUM_DECL
};

enum class ObjectFields {
  kDataOnly,
  kMaybePointers,
};

using MapHandles = std::vector<Handle<Map>>;
using MapHandlesSpan = v8::MemorySpan<Handle<Map>>;

#include "torque-generated/src/objects/map-tq.inc"

// All heap objects have a Map that describes their structure.
//  A Map contains information about:
//  - Size information about the object
//  - How to iterate over an object (for garbage collection)
//
// Map layout:
// +---------------+-------------------------------------------------+
// |   _ Type _    | _ Description _                                 |
// +---------------+-------------------------------------------------+
// | TaggedPointer | map - Always a pointer to the MetaMap root      |
// +---------------+-------------------------------------------------+
// | Int           | The first int field                             |
//  `---+----------+-------------------------------------------------+
//      | Byte     | [instance_size]                                 |
//      +----------+-------------------------------------------------+
//      | Byte     | If Map for a primitive type:                    |
//      |          |   native context index for constructor fn       |
//      |          | If Map for an Object type:                      |
//      |          |   inobject properties start offset in words     |
//      +----------+-------------------------------------------------+
//      | Byte     | [used_or_unused_instance_size_in_words]         |
//      |          | For JSObject in fast mode this byte encodes     |
//      |          | the size of the object that includes only       |
//      |          | the used property fields or the slack size      |
//      |          | in properties backing store.                    |
//      +----------+-------------------------------------------------+
//      | Byte     | [visitor_id]                                    |
// +----+----------+-------------------------------------------------+
// | Int           | The second int field                            |
//  `---+----------+-------------------------------------------------+
//      | Short    | [instance_type]                                 |
//      +----------+-------------------------------------------------+
//      | Byte     | [bit_field]                                     |
//      |          |   - has_non_instance_prototype (bit 0)          |
//      |          |   - is_callable (bit 1)                         |
//      |          |   - has_named_interceptor (bit 2)               |
//      |          |   - has_indexed_interceptor (bit 3)             |
//      |          |   - is_undetectable (bit 4)                     |
//      |          |   - is_access_check_needed (bit 5)              |
//      |          |   - is_constructor (bit 6)                      |
//      |          |   - has_prototype_slot (bit 7)                  |
//      +----------+-------------------------------------------------+
//      | Byte     | [bit_field2]                                    |
//      |          |   - new_target_is_base (bit 0)                  |
//      |          |   - is_immutable_proto (bit 1)                  |
//      |          |   - elements_kind (bits 2..7)                   |
// +----+----------+-------------------------------------------------+
// | Int           | [bit_field3]                                    |
// |               |   - enum_length (bit 0..9)                      |
// |               |   - number_of_own_descriptors (bit 10..19)      |
// |               |   - is_prototype_map (bit 20)                   |
// |               |   - is_dictionary_map (bit 21)                  |
// |               |   - owns_descriptors (bit 22)                   |
// |               |   - is_in_retained_map_list (bit 23)            |
// |               |   - is_deprecated (bit 24)                      |
// |               |   - is_unstable (bit 25)                        |
// |               |   - is_migration_target (bit 26)                |
// |               |   - is_extensible (bit 28)                      |
// |               |   - may_have_interesting_properties (bit 28)    |
// |               |   - construction_counter (bit 29..31)           |
// |               |                                                 |
// +*****************************************************************+
// | Int           | On systems with 64bit pointer types, there      |
// |               | is an unused 32bits after bit_field3            |
// +*****************************************************************+
// | TaggedPointer | [prototype]                                     |
// +---------------+-------------------------------------------------+
// | TaggedPointer | [constructor_or_back_pointer_or_native_context] |
// +---------------+-------------------------------------------------+
// | TaggedPointer | [instance_descriptors]                          |
// +*****************************************************************+
// | TaggedPointer | [dependent_code]                                |
// +---------------+-------------------------------------------------+
// | TaggedPointer | [prototype_validity_cell]                       |
// +---------------+-------------------------------------------------+
// | TaggedPointer | If Map is a prototype map:                      |
// |               |   [prototype_info]                              |
// |               | Else:                                           |
// |               |   [raw_transitions]                             |
// +---------------+-------------------------------------------------+

class Map : public TorqueGeneratedMap<Map, HeapObject> {
 public:
  // Instance size.
  // Size in bytes or kVariableSizeSentinel if instances do not have
  // a fixed size.
  DECL_INT_ACCESSORS(instance_size)
  // Size in words or kVariableSizeSentinel if instances do not have
  // a fixed size.
  DECL_INT_ACCESSORS(instance_size_in_words)

  // [inobject_properties_start_or_constructor_function_index]:
  // Provides access to the inobject properties start offset in words in case of
  // JSObject maps, or the constructor function index in case of primitive maps.
  DECL_INT_ACCESSORS(inobject_properties_start_or_constructor_function_index)

  // Get/set the in-object property area start offset in words in the object.
  inline int GetInObjectPropertiesStartInWords() const;
  inline void SetInObjectPropertiesStartInWords(int value);
  // Count of properties allocated in the object (JSObject only).
  inline int GetInObjectProperties() const;
  // Index of the constructor function in the native context (primitives only),
  // or the special sentinel value to indicate that there is no object wrapper
  // for the primitive (i.e. in case of null or undefined).
  static const int kNoConstructorFunctionIndex = 0;
  inline int GetConstructorFunctionIndex() const;
  inline void SetConstructorFunctionIndex(int value);
  static std::optional<Tagged<JSFunction>> GetConstructorFunction(
      Tagged<Map> map, Tagged<Context> native_context);

  // Retrieve interceptors.
  DECL_GETTER(GetNamedInterceptor, Tagged<InterceptorInfo>)
  DECL_GETTER(GetIndexedInterceptor, Tagged<InterceptorInfo>)

  // Instance type.
  DECL_PRIMITIVE_ACCESSORS(instance_type, InstanceType)

  // Returns the size of the used in-object area including object header
  // (only used for JSObject in fast mode, for the other kinds of objects it
  // is equal to the instance size).
  inline int UsedInstanceSize() const;

  inline bool HasOutOfObjectProperties() const;

  // Tells how many unused property fields (in-object or out-of object) are
  // available in the instance (only used for JSObject in fast mode).
  inline int UnusedPropertyFields() const;
  // Tells how many unused in-object property words are present.
  inline int UnusedInObjectProperties() const;
  // Updates the counters tracking unused fields in the object.
  inline void SetInObjectUnusedPropertyFields(int unused_property_fields);
  // Updates the counters tracking unused fields in the property array.
  inline void SetOutOfObjectUnusedPropertyFields(int unused_property_fields);
  inline void CopyUnusedPropertyFields(Tagged<Map> map);
  inline void CopyUnusedPropertyFieldsAdjustedForInstanceSize(Tagged<Map> map);
  inline void AccountAddedPropertyField();
  inline void AccountAddedOutOfObjectPropertyField(
      int unused_in_property_array);

  //
  // Bit field.
  //
  // The setter in this pair calls the relaxed setter if concurrent marking is
  // on, or performs the write non-atomically if it's off. The read is always
  // non-atomically. This is done to have wider TSAN coverage on the cases where
  // it's possible.
  DECL_PRIMITIVE_ACCESSORS(bit_field, uint8_t)

  // Atomic accessors, used for allowlisting legitimate concurrent accesses.
  DECL_PRIMITIVE_ACCESSORS(relaxed_bit_field, uint8_t)

  // Bit positions for |bit_field|.
  struct Bits1 {
    DEFINE_TORQUE_GENERATED_MAP_BIT_FIELDS1()
  };

  //
  // Bit field 2.
  //
  DECL_PRIMITIVE_ACCESSORS(bit_field2, uint8_t)

  // Bit positions for |bit_field2|.
  struct Bits2 {
    DEFINE_TORQUE_GENERATED_MAP_BIT_FIELDS2()
  };

  //
  // Bit field 3.
  //
  // {bit_field3} calls the relaxed accessors if concurrent marking is on, or
  // performs the read/write non-atomically if it's off. This is done to have
  // wider TSAN coverage on the cases where it's possible.
  DECL_PRIMITIVE_ACCESSORS(bit_field3, uint32_t)

  DECL_PRIMITIVE_ACCESSORS(relaxed_bit_field3, uint32_t)
  DECL_PRIMITIVE_ACCESSORS(release_acquire_bit_field3, uint32_t)

  // Clear uninitialized padding space. This ensures that the snapshot content
  // is deterministic. Depending on the V8 build mode there could be no padding.
  V8_INLINE void clear_padding();

  // Bit positions for |bit_field3|.
  struct Bits3 {
    DEFINE_TORQUE_GENERATED_MAP_BIT_FIELDS3()
  };

  // Ensure that Torque-defined bit widths for |bit_field3| are as expected.
  static_assert(Bits3::EnumLengthBits::kSize == kDescriptorIndexBitCount);
  static_assert(Bits3::NumberOfOwnDescriptorsBits::kSize ==
                kDescriptorIndexBitCount);

  static_assert(Bits3::NumberOfOwnDescriptorsBits::kMax >=
                kMaxNumberOfDescriptors);

  static const int kSlackTrackingCounterStart = 7;
  static const int kSlackTrackingCounterEnd = 1;
  static const int kNoSlackTracking = 0;
  static_assert(kSlackTrackingCounterStart <=
                Bits3::ConstructionCounterBits::kMax);

  // Inobject slack tracking is the way to reclaim unused inobject space.
  //
  // The instance size is initially determined by adding some slack to
  // expected_nof_properties (to allow for a few extra properties added
  // after the constructor). There is no guarantee that the extra space
  // will not be wasted.
  //
  // Here is the algorithm to reclaim the unused inobject space:
  // - Detect the first constructor call for this JSFunction.
  //   When it happens enter the "in progress" state: initialize construction
  //   counter in the initial_map.
  // - While the tracking is in progress initialize unused properties of a new
  //   object with one_pointer_filler_map instead of undefined_value (the "used"
  //   part is initialized with undefined_value as usual). This way they can
  //   be resized quickly and safely.
  // - Once enough objects have been created  compute the 'slack'
  //   (traverse the map transition tree starting from the
  //   initial_map and find the lowest value of unused_property_fields).
  // - Traverse the transition tree again and decrease the instance size
  //   of every map. Existing objects will resize automatically (they are
  //   filled with one_pointer_filler_map). All further allocations will
  //   use the adjusted instance size.
  // - SharedFunctionInfo's expected_nof_properties left unmodified since
  //   allocations made using different closures could actually create different
  //   kind of objects (see prototype inheritance pattern).
  //
  //  Important: inobject slack tracking is not attempted during the snapshot
  //  creation.

  static const int kGenerousAllocationCount =
      kSlackTrackingCounterStart - kSlackTrackingCounterEnd + 1;

  // Starts the tracking by initializing object constructions countdown counter.
  void StartInobjectSlackTracking();

  // True if the object constructions countdown counter is a range
  // [kSlackTrackingCounterEnd, kSlackTrackingCounterStart].
  inline bool IsInobjectSlackTrackingInProgress() const;

  // Does the tracking step.
  inline void InobjectSlackTrackingStep(Isolate* isolate);

  // Computes inobject slack for the transition tree starting at this initial
  // map.
  int ComputeMinObjectSlack(Isolate* isolate);
  inline int InstanceSizeFromSlack(int slack) const;

  // Tells whether the object in the prototype property will be used
  // for instances created from this function.  If the prototype
  // property is set to a value that is not a JSObject, the prototype
  // property will not be used to create instances of the function.
  // See ECMA-262, 13.2.2.
  DECL_BOOLEAN_ACCESSORS(has_non_instance_prototype)

  // Tells whether the instance has a [[Construct]] internal method.
  // This property is implemented according to ES6, section 7.2.4.
  DECL_BOOLEAN_ACCESSORS(is_constructor)

  // Tells whether the instance with this map may have properties for
  // interesting symbols on it.
  // An "interesting symbol" is one for which Name::IsInteresting()
  // returns true, i.e. a well-known symbol like @@toStringTag.
  DECL_BOOLEAN_ACCESSORS(may_have_interesting_properties)

  DECL_BOOLEAN_ACCESSORS(has_prototype_slot)

  // Records and queries whether the instance has a named interceptor.
  DECL_BOOLEAN_ACCESSORS(has_named_interceptor)

  // Records and queries whether the instance has an indexed interceptor.
  DECL_BOOLEAN_ACCESSORS(has_indexed_interceptor)

  // Tells whether the instance is undetectable.
  // An undetectable object is a special class of JSObject: 'typeof' operator
  // returns undefined, ToBoolean returns false. Otherwise it behaves like
  // a normal JS object.  It is useful for implementing undetectable
  // document.all in Firefox & Safari.
  // See https://bugzilla.mozilla.org/show_bug.cgi?id=248549.
  DECL_BOOLEAN_ACCESSORS(is_undetectable)

  // Tells whether the instance has a [[Call]] internal method.
  // This property is implemented according to ES6, section 7.2.3.
  DECL_BOOLEAN_ACCESSORS(is_callable)

  DECL_BOOLEAN_ACCESSORS(new_target_is_base)
  DECL_BOOLEAN_ACCESSORS(is_extensible)
  DECL_BOOLEAN_ACCESSORS(is_prototype_map)
  inline bool is_abandoned_prototype_map() const;
  inline bool has_prototype_info() const;
  inline bool TryGetPrototypeInfo(Tagged<PrototypeInfo>* result) const;

  // Whether the instance has been added to the retained map list by
  // Heap::AddRetainedMap.
  DECL_BOOLEAN_ACCESSORS(is_in_retained_map_list)

  DECL_PRIMITIVE_ACCESSORS(elements_kind, ElementsKind)

  // Tells whether the instance has fast elements that are only Smis.
  inline bool has_fast_smi_elements() const;

  // Tells whether the instance has fast elements.
  inline bool has_fast_object_elements() const;
  inline bool has_fast_smi_or_object_elements() const;
  inline bool has_fast_double_elements() const;
  inline bool has_fast_elements() const;
  inline bool has_fast_packed_elements() const;
  inline bool has_sloppy_arguments_elements() const;
  inline bool has_fast_sloppy_arguments_elements() const;
  inline bool has_fast_string_wrapper_elements() const;
  inline bool has_typed_array_or_rab_gsab_typed_array_elements() const;
  inline bool has_any_typed_array_or_wasm_array_elements() const;
  inline bool has_dictionary_elements() const;
  inline bool has_any_nonextensible_elements() const;
  inline bool has_nonextensible_elements() const;
  inline bool has_sealed_elements() const;
  inline bool has_frozen_elements() const;
  inline bool has_shared_array_elements() const;

  // Weakly checks whether a map is detached from all transition trees. If this
  // returns true, the map is guaranteed to be detached. If it returns false,
  // there is no guarantee it is attached.
  inline bool IsDetached(Isolate* isolate) const;

  // Returns true if there is an object with potentially read-only elements
  // in the prototype chain. It could be a Proxy, a string wrapper,
  // an object with DICTIONARY_ELEMENTS potentially containing read-only
  // elements or an object with any frozen elements, or a slow arguments object.
  bool ShouldCheckForReadOnlyElementsInPrototypeChain(Isolate* isolate);

  inline Tagged<Map> ElementsTransitionMap(Isolate* isolate,
                                           ConcurrencyMode cmode);

  inline Tagged<FixedArrayBase> GetInitialElements() const;

  // [raw_transitions]: Provides access to the transitions storage field.
  // Don't call set_raw_transitions() directly to overwrite transitions, use
  // the TransitionArray::ReplaceTransitions() wrapper instead!
  DECL_ACCESSORS(raw_transitions,
                 Tagged<UnionOf<Smi, MaybeWeak<Map>, TransitionArray>>)
  DECL_RELEASE_ACQUIRE_ACCESSORS(
      raw_transitions, Tagged<UnionOf<Smi, MaybeWeak<Map>, TransitionArray>>)
  // [prototype_info]: Per-prototype metadata. Aliased with transitions
  // (which prototype maps don't have).
  DECL_GETTER(prototype_info, Tagged<UnionOf<Smi, PrototypeInfo>>)
  DECL_RELEASE_ACQUIRE_ACCESSORS(prototype_info,
                                 Tagged<UnionOf<Smi, PrototypeInfo>>)
  // PrototypeInfo is created lazily using this helper (which installs it on
  // the given prototype's map).
  static Handle<PrototypeInfo> GetOrCreatePrototypeInfo(
      DirectHandle<JSObject> prototype, Isolate* isolate);
  static Handle<PrototypeInfo> GetOrCreatePrototypeInfo(
      DirectHandle<Map> prototype_map, Isolate* isolate);
  inline bool should_be_fast_prototype_map() const;
  static void SetShouldBeFastPrototypeMap(DirectHandle<Map> map, bool value,
                                          Isolate* isolate);

  // [prototype chain validity cell]: Associated with a prototype object,
  // stored in that object's map, indicates that prototype chains through this
  // object are currently valid. The cell will be invalidated and replaced when
  // the prototype chain changes. When there's nothing to guard (for example,
  // when direct prototype is null or Proxy) this function returns Smi with
  // |kPrototypeChainValid| sentinel value, which is zero.
  static Handle<UnionOf<Smi, Cell>> GetOrCreatePrototypeChainValidityCell(
      DirectHandle<Map> map, Isolate* isolate);
  static constexpr int kPrototypeChainValid = 0;
  static constexpr int kPrototypeChainInvalid = 1;
  static constexpr Tagged<Smi> kPrototypeChainValidSmi = Smi::zero();

  static bool IsPrototypeChainInvalidated(Tagged<Map> map);

  // Return the map of the root of object's prototype chain.
  Tagged<Map> GetPrototypeChainRootMap(Isolate* isolate) const;

  V8_EXPORT_PRIVATE Tagged<Map> FindRootMap(PtrComprCageBase cage_base) const;
  V8_EXPORT_PRIVATE Tagged<Map> FindFieldOwner(PtrComprCageBase cage_base,
                                               InternalIndex descriptor) const;

  inline int GetInObjectPropertyOffset(int index) const;

  class FieldCounts {
   public:
    FieldCounts(int mutable_count, int const_count)
        : mutable_count_(mutable_count), const_count_(const_count) {}

    int GetTotal() const { return mutable_count() + const_count(); }

    int mutable_count() const { return mutable_count_; }
    int const_count() const { return const_count_; }

   private:
    int mutable_count_;
    int const_count_;
  };

  FieldCounts GetFieldCounts() const;
  int NumberOfFields(ConcurrencyMode cmode) const;

  // TODO(ishell): candidate with JSObject::MigrateToMap().
  bool InstancesNeedRewriting(Tagged<Map> target, ConcurrencyMode cmode) const;
  bool InstancesNeedRewriting(Tagged<Map> target, int target_number_of_fields,
                              int target_inobject, int target_unused,
                              int* old_number_of_fields,
                              ConcurrencyMode cmode) const;
  // Returns true if the |field_type| is the most general one for
  // given |representation|.
  static inline bool IsMostGeneralFieldType(Representation representation,
                                            Tagged<FieldType> field_type);

  // Generalizes representation and field_type if objects with given
  // instance type can have fast elements that can be transitioned by
  // stubs or optimized code to more general elements kind.
  // This generalization is necessary in order to ensure that elements kind
  // transitions performed by stubs / optimized code don't silently transition
  // fields with representation "Tagged" back to "Smi" or "HeapObject" or
  // fields with HeapObject representation and "Any" type back to "Class" type.
  static inline void GeneralizeIfCanHaveTransitionableFastElementsKind(
      Isolate* isolate, InstanceType instance_type,
      Representation* representation, Handle<FieldType>* field_type);

  V8_EXPORT_PRIVATE static Handle<Map> PrepareForDataProperty(
      Isolate* isolate, Handle<Map> old_map, InternalIndex descriptor_number,
      PropertyConstness constness, DirectHandle<Object> value);

  V8_EXPORT_PRIVATE static Handle<Map> Normalize(
      Isolate* isolate, Handle<Map> map, ElementsKind new_elements_kind,
      Handle<JSPrototype> new_prototype, PropertyNormalizationMode mode,
      bool use_cache, const char* reason);
  V8_EXPORT_PRIVATE static Handle<Map> Normalize(
      Isolate* isolate, Handle<Map> map, ElementsKind new_elements_kind,
      Handle<JSPrototype> new_prototype, PropertyNormalizationMode mode,
      const char* reason) {
    const bool kUseCache = true;
    return Normalize(isolate, map, new_elements_kind, new_prototype, mode,
                     kUseCache, reason);
  }

  inline static Handle<Map> Normalize(Isolate* isolate, Handle<Map> fast_map,
                                      PropertyNormalizationMode mode,
                                      const char* reason);

  // Tells whether the map is used for JSObjects in dictionary mode (ie
  // normalized objects, ie objects for which HasFastProperties returns false).
  // A map can never be used for both dictionary mode and fast mode JSObjects.
  // False by default and for HeapObjects that are not JSObjects.
  DECL_BOOLEAN_ACCESSORS(is_dictionary_map)

  // Tells whether the instance needs security checks when accessing its
  // properties.
  DECL_BOOLEAN_ACCESSORS(is_access_check_needed)

  // [prototype]: implicit prototype object.
  DECL_ACCESSORS(prototype, Tagged<JSPrototype>)
  // TODO(jkummerow): make set_prototype private.
  V8_EXPORT_PRIVATE static void SetPrototype(
      Isolate* isolate, DirectHandle<Map> map, Handle<JSPrototype> prototype,
      bool enable_prototype_setup_mode = true);

  // Sets prototype and constructor fields to null. Can be called during
  // bootstrapping.
  inline void init_prototype_and_constructor_or_back_pointer(
      ReadOnlyRoots roots);

  // [constructor]: points back to the function or FunctionTemplateInfo
  // responsible for this map.
  // The field overlaps with the back pointer. All maps in a transition tree
  // have the same constructor, so maps with back pointers can walk the
  // back pointer chain until they find the map holding their constructor.
  // Returns null_value if there's neither a constructor function nor a
  // FunctionTemplateInfo available.
  // The field also overlaps with the native context pointer for context maps,
  // and with the Wasm type info for WebAssembly object maps.
  DECL_ACCESSORS(constructor_or_back_pointer, Tagged<Object>)
  DECL_RELAXED_ACCESSORS(constructor_or_back_pointer, Tagged<Object>)
  DECL_ACCESSORS(native_context, Tagged<NativeContext>)
  DECL_ACCESSORS(native_context_or_null, Tagged<Object>)
  DECL_GETTER(raw_native_context_or_null, Tagged<Object>)
  DECL_ACCESSORS(wasm_type_info, Tagged<WasmTypeInfo>)

  // Gets |constructor_or_back_pointer| field value from the root map.
  // The result might be null, JSFunction, FunctionTemplateInfo or a Tuple2
  // for JSFunctions with non-instance prototypes.
  DECL_GETTER(GetConstructorRaw, Tagged<Object>)

  // Gets constructor value from the root map. Unwraps Tuple2 in case of
  // JSFunction map with non-instance prototype.
  // The result returned might be null, JSFunction or FunctionTemplateInfo.
  DECL_GETTER(GetConstructor, Tagged<Object>)
  DECL_GETTER(GetFunctionTemplateInfo, Tagged<FunctionTemplateInfo>)
  inline void SetConstructor(Tagged<Object> constructor,
                             WriteBarrierMode mode = UPDATE_WRITE_BARRIER);
  // Constructor getter that performs at most the given number of steps
  // in the transition tree. Returns either the constructor or the map at
  // which the walk has stopped.
  inline Tagged<Object> TryGetConstructor(PtrComprCageBase cage_base,
                                          int max_steps);

  // Gets non-instance prototype value which is stored in Tuple2 in a
  // root map's |constructor_or_back_pointer| field.
  DECL_GETTER(GetNonInstancePrototype, Tagged<Object>)

  // [back pointer]: points back to the parent map from which a transition
  // leads to this map. The field overlaps with the constructor (see above).
  DECL_GETTER(GetBackPointer, Tagged<HeapObject>)
  inline void SetBackPointer(Tagged<HeapObject> value,
                             WriteBarrierMode mode = UPDATE_WRITE_BARRIER);
  inline bool TryGetBackPointer(PtrComprCageBase cage_base,
                                Tagged<Map>* back_pointer) const;

  // [instance descriptors]: describes the object.
  DECL_ACCESSORS(instance_descriptors, Tagged<DescriptorArray>)
  DECL_RELAXED_ACCESSORS(instance_descriptors, Tagged<DescriptorArray>)
  DECL_ACQUIRE_GETTER(instance_descriptors, Tagged<DescriptorArray>)
  V8_EXPORT_PRIVATE void SetInstanceDescriptors(
      Isolate* isolate, Tagged<DescriptorArray> descriptors,
      int number_of_own_descriptors,
      WriteBarrierMode barrier_mode = UPDATE_WRITE_BARRIER);

  inline void UpdateDescriptors(Isolate* isolate,
                                Tagged<DescriptorArray> descriptors,
                                int number_of_own_descriptors);
  inline void InitializeDescriptors(Isolate* isolate,
                                    Tagged<DescriptorArray> descriptors);

  // [dependent code]: list of optimized codes that weakly embed this map.
  DECL_ACCESSORS(dependent_code, Tagged<DependentCode>)

  // [prototype_validity_cell]: Cell containing the validity bit for prototype
  // chains or Tagged<Smi>(0) if uninitialized.
  // The meaning of this validity cell is different for prototype maps and
  // non-prototype maps.
  // For prototype maps the validity bit "guards" modifications of prototype
  // chains going through this object. When a prototype object changes, both its
  // own validity cell and those of all "downstream" prototypes are invalidated;
  // handlers for a given receiver embed the currently valid cell for that
  // receiver's prototype during their creation and check it on execution.
  // For non-prototype maps which are used as transitioning store handlers this
  // field contains the validity cell which guards modifications of this map's
  // prototype.
  DECL_RELAXED_ACCESSORS(prototype_validity_cell, Tagged<UnionOf<Smi, Cell>>)

  // Returns true if prototype validity cell value represents "valid" prototype
  // chain state.
  inline bool IsPrototypeValidityCellValid() const;

  // Returns true if this map belongs to the same native context as given map,
  // i.e. this map's meta map is equal to
```