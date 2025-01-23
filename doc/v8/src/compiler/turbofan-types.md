Response: Let's break down the thought process to analyze the C++ code and generate the summary and JavaScript examples.

**1. Understanding the Goal:**

The request asks for the functionality of the C++ code (`turbofan-types.cc`) and its relation to JavaScript, including examples. This means we need to understand what "Turbofan types" are in the context of V8's compiler and how they relate to JavaScript's dynamic typing.

**2. Initial Scan and Keywords:**

A quick scan of the code reveals key terms:

* `compiler/turbofan-types.h`: This suggests the code defines data structures and operations related to type representation within the Turbofan compiler.
* `RangeType`, `BitsetType`, `UnionType`, `HeapConstantType`, `OtherNumberConstantType`, `TupleType`, `WasmType`: These are likely the core type representation classes.
* `Min`, `Max`, `Intersect`, `Union`, `Overlap`, `Contains`, `Is`, `Maybe`: These are operations performed on these types.
* `JSHeapBroker`: This hints at interaction with V8's heap and JavaScript objects.
* `TurbofanType`:  This seems to be the high-level abstraction for these compiler types.
* `#ifdef V8_ENABLE_WEBASSEMBLY`:  Indicates support for WebAssembly types.

**3. Core Functionality Identification:**

Based on the keywords and the structure of the code, it becomes clear that the primary function of this file is to define and manipulate a system of *internal* types used by the Turbofan compiler. These types are more detailed and precise than the runtime JavaScript types. The core functionalities revolve around:

* **Representing various types:** Numbers (with ranges and special values like NaN and -0), JavaScript objects (with distinctions like arrays, functions, strings), and WebAssembly types.
* **Performing operations on types:** Intersection, union, checking for overlap, containment, and subtyping.
* **Calculating minimum and maximum values:**  For numerical types.
* **Converting between different type representations:** Bitsets seem to be a fundamental representation.

**4. Connecting to JavaScript:**

The crucial part is understanding *why* these internal types exist and how they connect to JavaScript. The key insight is that JavaScript is dynamically typed. The compiler needs to *infer* and track more specific type information than what's available at runtime to perform optimizations.

* **Type Inference:** Turbofan analyzes JavaScript code to infer more precise types than just "object" or "number." For example, it might infer that a variable is always an integer within a certain range.
* **Optimization:** Knowing these more specific types allows Turbofan to generate more efficient machine code. For instance, if it knows a variable is always an integer, it can use integer arithmetic instructions instead of more general (and slower) floating-point operations.
* **Handling Dynamicism:**  The type system needs to be able to represent uncertainty and combine different possibilities (hence the `UnionType`).

**5. Generating JavaScript Examples:**

Now, let's think about how to illustrate this with JavaScript examples. We need examples where the compiler would likely benefit from using these internal types:

* **Number Ranges:**  Simple arithmetic operations where the compiler could infer integer types or specific ranges. `x + 1` where `x` is known to be a small integer is a good starting point.
* **Object Types:** Examples showing how Turbofan differentiates between various object types: arrays, strings, functions. Accessing properties or calling methods on these objects are good examples.
* **Special Values:**  Illustrating how NaN and -0 are handled as distinct types.

**6. Structuring the Explanation:**

Organize the information logically:

* Start with a concise summary of the file's purpose.
* Explain the core concepts like internal type representation and the main type classes.
* Detail the operations performed on these types.
* Clearly explain the relationship to JavaScript's dynamic typing and the benefits for optimization.
* Provide concrete JavaScript examples that demonstrate the connection.

**7. Refinement and Detail:**

Review the generated explanation for clarity and accuracy. Ensure the JavaScript examples are simple and directly illustrate the concepts. For instance, initially, I might have thought of more complex object examples, but simpler examples like array indexing or string concatenation are more effective at illustrating the basic idea. Also, emphasize the *compiler's internal perspective* – the types are not directly visible to the JavaScript programmer.

By following this thought process, combining code analysis with an understanding of compiler principles, we can effectively explain the functionality of `turbofan-types.cc` and its connection to JavaScript.
This C++ source file, `v8/src/compiler/turbofan-types.cc`, defines and implements a type system used internally by the **Turbofan optimizing compiler** in V8. Its primary function is to represent and manipulate type information about JavaScript values during the compilation process.

Here's a breakdown of its functionality:

**Core Functionality:**

* **Defining a Rich Type System:**  It introduces various C++ classes and structures to represent different kinds of types beyond basic JavaScript types like "number" or "object". These internal types are more granular and allow Turbofan to reason more precisely about the values being manipulated. Key type representations include:
    * **`BitsetType`:**  Represents sets of primitive JavaScript types (like `Number`, `String`, `Boolean`, `Null`, `Undefined`, etc.) using bitmasks for efficient set operations. It also includes finer-grained number types (e.g., `Signed32`, `Unsigned32`).
    * **`RangeType`:** Represents numerical ranges (e.g., numbers between 5 and 10, excluding infinity).
    * **`UnionType`:** Represents the union of multiple types (e.g., a value that could be either a string or a number).
    * **`HeapConstantType`:** Represents a specific constant JavaScript object.
    * **`OtherNumberConstantType`:** Represents specific non-integer, non-NaN, non-zero numbers.
    * **`TupleType`:** Represents a fixed-size array of types (used for representing the types of elements in a tuple-like structure).
    * **`WasmType`:** Represents WebAssembly value types.

* **Implementing Type Operations:** The file provides functions to perform various operations on these internal types, such as:
    * **`Intersect`:**  Calculates the intersection of two types (the type that contains values common to both).
    * **`Union`:** Calculates the union of two types (the type that contains values from either type).
    * **`Is` (subtype check):** Determines if one type is a subtype of another (all values of the first type are also values of the second).
    * **`Maybe` (overlap check):** Determines if two types have any values in common.
    * **`Contains`:**  Checks if one range contains another.
    * **`Overlap`:** Checks if two ranges overlap.
    * **`Min` and `Max`:**  Calculates the minimum and maximum values for numeric types.
    * **`BitsetGlb` and `BitsetLub`:**  Calculate the greatest lower bound and least upper bound bitsets for a given type.

* **Normalization and Simplification:** Functions like `NormalizeUnion` and `NormalizeRangeAndBitset` are used to simplify and optimize the type representations.

* **Conversion to Heap Representation:** The `AllocateOnHeap` function allows these internal types to be represented as actual JavaScript objects (`TurbofanType`) on the heap, which can be used for type assertions and other runtime checks during debugging or development.

**Relationship to JavaScript Functionality:**

This file is **crucially important for the performance of JavaScript code**. While JavaScript is dynamically typed, the Turbofan compiler attempts to infer more precise types during compilation. This allows it to:

1. **Optimize code:** By knowing the possible types of variables and expressions, Turbofan can generate more specialized and efficient machine code. For example, if it knows a variable is always an integer within a certain range, it can use integer arithmetic instructions instead of slower general-purpose number operations.
2. **Eliminate runtime type checks:**  If the compiler can prove that a certain operation will always be valid given the inferred types, it can skip runtime type checks, further improving performance.
3. **Handle dynamic features:** The type system needs to be flexible enough to represent the dynamic nature of JavaScript, including the possibility of values having different types at different times. This is where `UnionType` comes in handy.

**JavaScript Examples (Illustrating how Turbofan might use these internal types):**

```javascript
function add(x, y) {
  return x + y;
}

add(5, 10); // Here, Turbofan might infer x and y are within a certain integer range.
add("hello", " world"); // Here, Turbofan might infer x and y are strings.
add(3.14, 2.71); // Here, Turbofan might infer x and y are floating-point numbers.
add(5, "test"); // Here, Turbofan might infer a union type for the result
                 // because the '+' operator can perform addition or concatenation.

function getElement(arr, index) {
  return arr[index];
}

const numbers = [1, 2, 3];
getElement(numbers, 1); // Turbofan might infer that 'arr' is an array of numbers
                        // and the return type is likely a number.

const mixed = [1, "hello", true];
getElement(mixed, 0); // Turbofan might infer a union type (number | string | boolean)
                       // for the return value.

function possiblyNull(val) {
  if (Math.random() < 0.5) {
    return null;
  }
  return val;
}

let result = possiblyNull(10); // Turbofan might infer a union type (number | null) for 'result'.
```

**Explanation of the Examples in Relation to `turbofan-types.cc`:**

* **`add(5, 10)`:** Turbofan could represent the types of `x` and `y` using `RangeType` (e.g., integers within a certain range) or specific `BitsetType` values (e.g., `kSignedSmall`). This allows for optimized integer addition.
* **`add("hello", " world")`:**  Turbofan would use `BitsetType::kString` to represent the types of `x` and `y`, leading to optimized string concatenation.
* **`add(5, "test")`:** Turbofan would likely create a `UnionType` representing the possible result types (number or string) because the `+` operator is overloaded in JavaScript.
* **`getElement(numbers, 1)`:**  Turbofan could infer that `numbers` is an array with elements of type `BitsetType::kNumber` and the return type of `getElement` is also `BitsetType::kNumber`.
* **`getElement(mixed, 0)`:**  Turbofan would use a `UnionType` to represent the possible types of elements in the `mixed` array.
* **`possiblyNull(10)`:** Turbofan would use a `UnionType` combining `BitsetType::kNumber` and `BitsetType::kNull` to represent the possible types of `result`.

**In Summary:**

`v8/src/compiler/turbofan-types.cc` is a fundamental part of V8's optimizing compiler. It defines a sophisticated internal type system that allows Turbofan to reason about JavaScript values with greater precision than the language's dynamic typing suggests. This enables significant performance optimizations by generating more efficient machine code and reducing the need for runtime type checks. It acts as a bridge between the dynamic nature of JavaScript and the static requirements of efficient compilation.

### 提示词
```
这是目录为v8/src/compiler/turbofan-types.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/turbofan-types.h"

#include <iomanip>

#include "src/compiler/js-heap-broker.h"
#include "src/numbers/conversions-inl.h"
#include "src/objects/elements-kind.h"
#include "src/objects/instance-type.h"
#include "src/objects/turbofan-types.h"
#include "src/utils/ostreams.h"

#ifdef V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-subtyping.h"
#endif

namespace v8 {
namespace internal {
namespace compiler {

// -----------------------------------------------------------------------------
// Range-related helper functions.

bool RangeType::Limits::IsEmpty() { return this->min > this->max; }

RangeType::Limits RangeType::Limits::Intersect(Limits lhs, Limits rhs) {
  DisallowGarbageCollection no_gc;
  Limits result(lhs);
  if (lhs.min < rhs.min) result.min = rhs.min;
  if (lhs.max > rhs.max) result.max = rhs.max;
  return result;
}

RangeType::Limits RangeType::Limits::Union(Limits lhs, Limits rhs) {
  DisallowGarbageCollection no_gc;
  if (lhs.IsEmpty()) return rhs;
  if (rhs.IsEmpty()) return lhs;
  Limits result(lhs);
  if (lhs.min > rhs.min) result.min = rhs.min;
  if (lhs.max < rhs.max) result.max = rhs.max;
  return result;
}

bool Type::Overlap(const RangeType* lhs, const RangeType* rhs) {
  DisallowGarbageCollection no_gc;
  return !RangeType::Limits::Intersect(RangeType::Limits(lhs),
                                       RangeType::Limits(rhs))
              .IsEmpty();
}

bool Type::Contains(const RangeType* lhs, const RangeType* rhs) {
  DisallowGarbageCollection no_gc;
  return lhs->Min() <= rhs->Min() && rhs->Max() <= lhs->Max();
}

// -----------------------------------------------------------------------------
// Min and Max computation.

double Type::Min() const {
  DCHECK(this->Is(Number()));
  DCHECK(!this->Is(NaN()));
  if (this->IsBitset()) return BitsetType::Min(this->AsBitset());
  if (this->IsUnion()) {
    double min = +V8_INFINITY;
    for (int i = 1, n = AsUnion()->Length(); i < n; ++i) {
      min = std::min(min, AsUnion()->Get(i).Min());
    }
    Type bitset = AsUnion()->Get(0);
    if (!bitset.Is(NaN())) min = std::min(min, bitset.Min());
    return min;
  }
  if (this->IsRange()) return this->AsRange()->Min();
  DCHECK(this->IsOtherNumberConstant());
  return this->AsOtherNumberConstant()->Value();
}

double Type::Max() const {
  DCHECK(this->Is(Number()));
  DCHECK(!this->Is(NaN()));
  if (this->IsBitset()) return BitsetType::Max(this->AsBitset());
  if (this->IsUnion()) {
    double max = -V8_INFINITY;
    for (int i = 1, n = this->AsUnion()->Length(); i < n; ++i) {
      max = std::max(max, this->AsUnion()->Get(i).Max());
    }
    Type bitset = this->AsUnion()->Get(0);
    if (!bitset.Is(NaN())) max = std::max(max, bitset.Max());
    return max;
  }
  if (this->IsRange()) return this->AsRange()->Max();
  DCHECK(this->IsOtherNumberConstant());
  return this->AsOtherNumberConstant()->Value();
}

// -----------------------------------------------------------------------------
// Glb and lub computation.

// The largest bitset subsumed by this type.
Type::bitset Type::BitsetGlb() const {
  DisallowGarbageCollection no_gc;
  // Fast case.
  if (IsBitset()) {
    return AsBitset();
  } else if (IsUnion()) {
    SLOW_DCHECK(AsUnion()->Wellformed());
    return AsUnion()->Get(0).BitsetGlb() |
           AsUnion()->Get(1).BitsetGlb();  // Shortcut.
  } else if (IsRange()) {
    bitset glb = BitsetType::Glb(AsRange()->Min(), AsRange()->Max());
    return glb;
  } else {
    return BitsetType::kNone;
  }
}

// The smallest bitset subsuming this type, possibly not a proper one.
Type::bitset Type::BitsetLub() const {
  DisallowGarbageCollection no_gc;
  if (IsBitset()) return AsBitset();
  if (IsUnion()) {
    // Take the representation from the first element, which is always
    // a bitset.
    bitset lub = AsUnion()->Get(0).BitsetLub();
    for (int i = 0, n = AsUnion()->Length(); i < n; ++i) {
      // Other elements only contribute their semantic part.
      lub |= AsUnion()->Get(i).BitsetLub();
    }
    return lub;
  }
  if (IsHeapConstant()) return AsHeapConstant()->Lub();
  if (IsOtherNumberConstant()) {
    return AsOtherNumberConstant()->Lub();
  }
  if (IsRange()) return AsRange()->Lub();
  if (IsTuple()) return BitsetType::kOtherInternal;
#if V8_ENABLE_WEBASSEMBLY
  if (IsWasm()) return static_cast<const WasmType*>(ToTypeBase())->Lub();
#endif
  UNREACHABLE();
}

// TODO(neis): Once the broker mode kDisabled is gone, change the input type to
// MapRef and get rid of the HeapObjectType class.
template <typename MapRefLike>
Type::bitset BitsetType::Lub(MapRefLike map, JSHeapBroker* broker) {
  switch (map.instance_type()) {
    case CONS_TWO_BYTE_STRING_TYPE:
    case CONS_ONE_BYTE_STRING_TYPE:
    case THIN_TWO_BYTE_STRING_TYPE:
    case THIN_ONE_BYTE_STRING_TYPE:
    case SLICED_TWO_BYTE_STRING_TYPE:
    case SLICED_ONE_BYTE_STRING_TYPE:
    case EXTERNAL_TWO_BYTE_STRING_TYPE:
    case EXTERNAL_ONE_BYTE_STRING_TYPE:
    case UNCACHED_EXTERNAL_TWO_BYTE_STRING_TYPE:
    case UNCACHED_EXTERNAL_ONE_BYTE_STRING_TYPE:
    case SEQ_TWO_BYTE_STRING_TYPE:
    case SEQ_ONE_BYTE_STRING_TYPE:
    case SHARED_SEQ_TWO_BYTE_STRING_TYPE:
    case SHARED_SEQ_ONE_BYTE_STRING_TYPE:
    case SHARED_EXTERNAL_TWO_BYTE_STRING_TYPE:
    case SHARED_EXTERNAL_ONE_BYTE_STRING_TYPE:
    case SHARED_UNCACHED_EXTERNAL_TWO_BYTE_STRING_TYPE:
    case SHARED_UNCACHED_EXTERNAL_ONE_BYTE_STRING_TYPE:
      return kString;
    case EXTERNAL_INTERNALIZED_TWO_BYTE_STRING_TYPE:
    case EXTERNAL_INTERNALIZED_ONE_BYTE_STRING_TYPE:
    case UNCACHED_EXTERNAL_INTERNALIZED_TWO_BYTE_STRING_TYPE:
    case UNCACHED_EXTERNAL_INTERNALIZED_ONE_BYTE_STRING_TYPE:
    case INTERNALIZED_TWO_BYTE_STRING_TYPE:
    case INTERNALIZED_ONE_BYTE_STRING_TYPE:
      return kInternalizedString;
    case SYMBOL_TYPE:
      return kSymbol;
    case BIGINT_TYPE:
      return kBigInt;
    case ODDBALL_TYPE:
      switch (map.oddball_type(broker)) {
        case OddballType::kNone:
          break;
        case OddballType::kBoolean:
          return kBoolean;
        case OddballType::kNull:
          return kNull;
        case OddballType::kUndefined:
          return kUndefined;
      }
      UNREACHABLE();
    case HOLE_TYPE:
      // Holes have a single map and we should have distinguished them earlier
      // by pointer comparison on the value.
      UNREACHABLE();
    case HEAP_NUMBER_TYPE:
      return kNumber;
    case JS_ARRAY_ITERATOR_PROTOTYPE_TYPE:
    case JS_ITERATOR_PROTOTYPE_TYPE:
    case JS_MAP_ITERATOR_PROTOTYPE_TYPE:
    case JS_OBJECT_PROTOTYPE_TYPE:
    case JS_OBJECT_TYPE:
    case JS_PROMISE_PROTOTYPE_TYPE:
    case JS_REG_EXP_PROTOTYPE_TYPE:
    case JS_SET_ITERATOR_PROTOTYPE_TYPE:
    case JS_SET_PROTOTYPE_TYPE:
    case JS_STRING_ITERATOR_PROTOTYPE_TYPE:
    case JS_ARGUMENTS_OBJECT_TYPE:
    case JS_ERROR_TYPE:
    case JS_EXTERNAL_OBJECT_TYPE:
    case JS_GLOBAL_OBJECT_TYPE:
    case JS_GLOBAL_PROXY_TYPE:
    case JS_API_OBJECT_TYPE:
    case JS_SPECIAL_API_OBJECT_TYPE:
    case JS_TYPED_ARRAY_PROTOTYPE_TYPE:
      if (map.is_undetectable()) {
        // Currently we assume that every undetectable receiver is also
        // callable, which is what we need to support document.all.  We
        // could add another Type bit to support other use cases in the
        // future if necessary.
        DCHECK(map.is_callable());
        return kOtherUndetectable;
      }
      if (map.is_callable()) {
        return kOtherCallable;
      }
      return kOtherObject;
    case JS_ARRAY_TYPE:
      return kArray;
    case JS_PRIMITIVE_WRAPPER_TYPE: {
      DCHECK(!map.is_callable());
      DCHECK(!map.is_undetectable());
      auto elements_kind = map.elements_kind();
      if (elements_kind == ElementsKind::FAST_STRING_WRAPPER_ELEMENTS ||
          elements_kind == ElementsKind::SLOW_STRING_WRAPPER_ELEMENTS) {
        return kStringWrapper;
      }
      return kOtherObject;
    }
    case JS_MESSAGE_OBJECT_TYPE:
    case JS_DATE_TYPE:
#ifdef V8_INTL_SUPPORT
    case JS_V8_BREAK_ITERATOR_TYPE:
    case JS_COLLATOR_TYPE:
    case JS_DATE_TIME_FORMAT_TYPE:
    case JS_DISPLAY_NAMES_TYPE:
    case JS_DURATION_FORMAT_TYPE:
    case JS_LIST_FORMAT_TYPE:
    case JS_LOCALE_TYPE:
    case JS_NUMBER_FORMAT_TYPE:
    case JS_PLURAL_RULES_TYPE:
    case JS_RELATIVE_TIME_FORMAT_TYPE:
    case JS_SEGMENT_ITERATOR_TYPE:
    case JS_SEGMENTER_TYPE:
    case JS_SEGMENTS_TYPE:
#endif  // V8_INTL_SUPPORT
    case JS_CONTEXT_EXTENSION_OBJECT_TYPE:
    case JS_DISPOSABLE_STACK_BASE_TYPE:
    case JS_ASYNC_DISPOSABLE_STACK_TYPE:
    case JS_SYNC_DISPOSABLE_STACK_TYPE:
    case JS_GENERATOR_OBJECT_TYPE:
    case JS_ASYNC_FUNCTION_OBJECT_TYPE:
    case JS_ASYNC_GENERATOR_OBJECT_TYPE:
    case JS_MODULE_NAMESPACE_TYPE:
    case JS_ARRAY_BUFFER_TYPE:
    case JS_ARRAY_ITERATOR_TYPE:
    case JS_REG_EXP_TYPE:
    case JS_REG_EXP_STRING_ITERATOR_TYPE:
    case JS_TYPED_ARRAY_TYPE:
    case JS_DATA_VIEW_TYPE:
    case JS_RAB_GSAB_DATA_VIEW_TYPE:
    case JS_SET_TYPE:
    case JS_MAP_TYPE:
    case JS_SET_KEY_VALUE_ITERATOR_TYPE:
    case JS_SET_VALUE_ITERATOR_TYPE:
    case JS_MAP_KEY_ITERATOR_TYPE:
    case JS_MAP_KEY_VALUE_ITERATOR_TYPE:
    case JS_MAP_VALUE_ITERATOR_TYPE:
    case JS_STRING_ITERATOR_TYPE:
    case JS_ASYNC_FROM_SYNC_ITERATOR_TYPE:
    case JS_ITERATOR_MAP_HELPER_TYPE:
    case JS_ITERATOR_FILTER_HELPER_TYPE:
    case JS_ITERATOR_TAKE_HELPER_TYPE:
    case JS_ITERATOR_DROP_HELPER_TYPE:
    case JS_ITERATOR_FLAT_MAP_HELPER_TYPE:
    case JS_VALID_ITERATOR_WRAPPER_TYPE:
    case JS_FINALIZATION_REGISTRY_TYPE:
    case JS_WEAK_MAP_TYPE:
    case JS_WEAK_REF_TYPE:
    case JS_WEAK_SET_TYPE:
    case JS_PROMISE_TYPE:
    case JS_SHADOW_REALM_TYPE:
    case JS_SHARED_ARRAY_TYPE:
    case JS_SHARED_STRUCT_TYPE:
    case JS_ATOMICS_CONDITION_TYPE:
    case JS_ATOMICS_MUTEX_TYPE:
    case JS_TEMPORAL_CALENDAR_TYPE:
    case JS_TEMPORAL_DURATION_TYPE:
    case JS_TEMPORAL_INSTANT_TYPE:
    case JS_TEMPORAL_PLAIN_DATE_TYPE:
    case JS_TEMPORAL_PLAIN_DATE_TIME_TYPE:
    case JS_TEMPORAL_PLAIN_MONTH_DAY_TYPE:
    case JS_TEMPORAL_PLAIN_TIME_TYPE:
    case JS_TEMPORAL_PLAIN_YEAR_MONTH_TYPE:
    case JS_TEMPORAL_TIME_ZONE_TYPE:
    case JS_TEMPORAL_ZONED_DATE_TIME_TYPE:
    case JS_RAW_JSON_TYPE:
#if V8_ENABLE_WEBASSEMBLY
    case WASM_GLOBAL_OBJECT_TYPE:
    case WASM_INSTANCE_OBJECT_TYPE:
    case WASM_MEMORY_OBJECT_TYPE:
    case WASM_MODULE_OBJECT_TYPE:
    case WASM_SUSPENDER_OBJECT_TYPE:
    case WASM_SUSPENDING_OBJECT_TYPE:
    case WASM_TABLE_OBJECT_TYPE:
    case WASM_TAG_OBJECT_TYPE:
    case WASM_EXCEPTION_PACKAGE_TYPE:
    case WASM_VALUE_OBJECT_TYPE:
#endif  // V8_ENABLE_WEBASSEMBLY
    case WEAK_CELL_TYPE:
      DCHECK(!map.is_callable());
      DCHECK(!map.is_undetectable());
      return kOtherObject;
#if V8_ENABLE_WEBASSEMBLY
    case WASM_STRUCT_TYPE:
    case WASM_ARRAY_TYPE:
      return kWasmObject;
#endif  // V8_ENABLE_WEBASSEMBLY
    case JS_BOUND_FUNCTION_TYPE:
      DCHECK(!map.is_undetectable());
      return kBoundFunction;
    case JS_WRAPPED_FUNCTION_TYPE:
      DCHECK(!map.is_undetectable());
      return kOtherCallable;
    case JS_FUNCTION_TYPE:
    case JS_PROMISE_CONSTRUCTOR_TYPE:
    case JS_REG_EXP_CONSTRUCTOR_TYPE:
    case JS_ARRAY_CONSTRUCTOR_TYPE:
#define TYPED_ARRAY_CONSTRUCTORS_SWITCH(Type, type, TYPE, Ctype) \
  case TYPE##_TYPED_ARRAY_CONSTRUCTOR_TYPE:
      TYPED_ARRAYS(TYPED_ARRAY_CONSTRUCTORS_SWITCH)
#undef TYPED_ARRAY_CONSTRUCTORS_SWITCH
      DCHECK(!map.is_undetectable());
      return kCallableFunction;
    case JS_CLASS_CONSTRUCTOR_TYPE:
      return kClassConstructor;
    case JS_PROXY_TYPE:
      DCHECK(!map.is_undetectable());
      if (map.is_callable()) return kCallableProxy;
      return kOtherProxy;
    case MAP_TYPE:
    case ALLOCATION_SITE_TYPE:
    case ACCESSOR_INFO_TYPE:
    case SHARED_FUNCTION_INFO_TYPE:
    case FUNCTION_TEMPLATE_INFO_TYPE:
    case FUNCTION_TEMPLATE_RARE_DATA_TYPE:
    case ACCESSOR_PAIR_TYPE:
    case EMBEDDER_DATA_ARRAY_TYPE:
    case FIXED_ARRAY_TYPE:
    case CLASS_BOILERPLATE_TYPE:
    case PROPERTY_DESCRIPTOR_OBJECT_TYPE:
    case HASH_TABLE_TYPE:
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
    case ORDERED_NAME_DICTIONARY_TYPE:
    case NAME_DICTIONARY_TYPE:
    case GLOBAL_DICTIONARY_TYPE:
    case NUMBER_DICTIONARY_TYPE:
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
    case EPHEMERON_HASH_TABLE_TYPE:
    case WEAK_FIXED_ARRAY_TYPE:
    case WEAK_ARRAY_LIST_TYPE:
    case FIXED_DOUBLE_ARRAY_TYPE:
    case FEEDBACK_METADATA_TYPE:
    case BYTE_ARRAY_TYPE:
    case BYTECODE_ARRAY_TYPE:
    case OBJECT_BOILERPLATE_DESCRIPTION_TYPE:
    case ARRAY_BOILERPLATE_DESCRIPTION_TYPE:
    case REG_EXP_BOILERPLATE_DESCRIPTION_TYPE:
    case TRANSITION_ARRAY_TYPE:
    case FEEDBACK_CELL_TYPE:
    case CLOSURE_FEEDBACK_CELL_ARRAY_TYPE:
    case FEEDBACK_VECTOR_TYPE:
    case PROPERTY_ARRAY_TYPE:
    case FOREIGN_TYPE:
    case SCOPE_INFO_TYPE:
    case SCRIPT_CONTEXT_TABLE_TYPE:
    case AWAIT_CONTEXT_TYPE:
    case BLOCK_CONTEXT_TYPE:
    case CATCH_CONTEXT_TYPE:
    case DEBUG_EVALUATE_CONTEXT_TYPE:
    case EVAL_CONTEXT_TYPE:
    case FUNCTION_CONTEXT_TYPE:
    case MODULE_CONTEXT_TYPE:
    case MODULE_REQUEST_TYPE:
    case NATIVE_CONTEXT_TYPE:
    case SCRIPT_CONTEXT_TYPE:
    case WITH_CONTEXT_TYPE:
    case SCRIPT_TYPE:
    case INSTRUCTION_STREAM_TYPE:
    case CODE_TYPE:
    case PROPERTY_CELL_TYPE:
    case CONTEXT_SIDE_PROPERTY_CELL_TYPE:
    case SOURCE_TEXT_MODULE_TYPE:
    case SOURCE_TEXT_MODULE_INFO_ENTRY_TYPE:
    case SYNTHETIC_MODULE_TYPE:
    case CELL_TYPE:
    case PREPARSE_DATA_TYPE:
    case UNCOMPILED_DATA_WITHOUT_PREPARSE_DATA_TYPE:
    case UNCOMPILED_DATA_WITH_PREPARSE_DATA_TYPE:
    case COVERAGE_INFO_TYPE:
    case REG_EXP_DATA_TYPE:
    case ATOM_REG_EXP_DATA_TYPE:
    case IR_REG_EXP_DATA_TYPE:
#if V8_ENABLE_WEBASSEMBLY
    case WASM_TYPE_INFO_TYPE:
#endif  // V8_ENABLE_WEBASSEMBLY
      return kOtherInternal;

    // Remaining instance types are unsupported for now. If any of them do
    // require bit set types, they should get kOtherInternal.
    default:
      UNREACHABLE();
  }
  UNREACHABLE();
}

// Explicit instantiation.
template Type::bitset BitsetType::Lub<MapRef>(MapRef map, JSHeapBroker* broker);

Type::bitset BitsetType::Lub(double value) {
  DisallowGarbageCollection no_gc;
  if (IsMinusZero(value)) return kMinusZero;
  if (std::isnan(value)) return kNaN;
  if (IsUint32Double(value) || IsInt32Double(value)) return Lub(value, value);
  return kOtherNumber;
}

// Minimum values of plain numeric bitsets.
const BitsetType::Boundary BitsetType::BoundariesArray[] = {
    {kOtherNumber, kPlainNumber, -V8_INFINITY},
    {kOtherSigned32, kNegative32, kMinInt},
    {kNegative31, kNegative31, -0x40000000},
    {kUnsigned30, kUnsigned30, 0},
    {kOtherUnsigned31, kUnsigned31, 0x40000000},
    {kOtherUnsigned32, kUnsigned32, 0x80000000},
    {kOtherNumber, kPlainNumber, static_cast<double>(kMaxUInt32) + 1}};

const BitsetType::Boundary* BitsetType::Boundaries() { return BoundariesArray; }

size_t BitsetType::BoundariesSize() {
  // Windows doesn't like arraysize here.
  // return arraysize(BoundariesArray);
  return 7;
}

Type::bitset BitsetType::ExpandInternals(Type::bitset bits) {
  DCHECK_IMPLIES(bits & kOtherString, (bits & kString) == kString);
  DisallowGarbageCollection no_gc;
  if (!(bits & kPlainNumber)) return bits;  // Shortcut.
  const Boundary* boundaries = Boundaries();
  for (size_t i = 0; i < BoundariesSize(); ++i) {
    DCHECK(BitsetType::Is(boundaries[i].internal, boundaries[i].external));
    if (bits & boundaries[i].internal) bits |= boundaries[i].external;
  }
  return bits;
}

Type::bitset BitsetType::Lub(double min, double max) {
  DisallowGarbageCollection no_gc;
  bitset lub = kNone;
  const Boundary* mins = Boundaries();

  for (size_t i = 1; i < BoundariesSize(); ++i) {
    if (min < mins[i].min) {
      lub |= mins[i - 1].internal;
      if (max < mins[i].min) return lub;
    }
  }
  return lub | mins[BoundariesSize() - 1].internal;
}

Type::bitset BitsetType::NumberBits(bitset bits) { return bits & kPlainNumber; }

Type::bitset BitsetType::Glb(double min, double max) {
  DisallowGarbageCollection no_gc;
  bitset glb = kNone;
  const Boundary* mins = Boundaries();

  // If the range does not touch 0, the bound is empty.
  if (max < -1 || min > 0) return glb;

  for (size_t i = 1; i + 1 < BoundariesSize(); ++i) {
    if (min <= mins[i].min) {
      if (max + 1 < mins[i + 1].min) break;
      glb |= mins[i].external;
    }
  }
  // OtherNumber also contains float numbers, so it can never be
  // in the greatest lower bound.
  return glb & ~(kOtherNumber);
}

double BitsetType::Min(bitset bits) {
  DisallowGarbageCollection no_gc;
  DCHECK(Is(bits, kNumber));
  DCHECK(!Is(bits, kNaN));
  const Boundary* mins = Boundaries();
  bool mz = bits & kMinusZero;
  for (size_t i = 0; i < BoundariesSize(); ++i) {
    if (Is(mins[i].internal, bits)) {
      return mz ? std::min(0.0, mins[i].min) : mins[i].min;
    }
  }
  DCHECK(mz);
  return 0;
}

double BitsetType::Max(bitset bits) {
  DisallowGarbageCollection no_gc;
  DCHECK(Is(bits, kNumber));
  DCHECK(!Is(bits, kNaN));
  const Boundary* mins = Boundaries();
  bool mz = bits & kMinusZero;
  if (BitsetType::Is(mins[BoundariesSize() - 1].internal, bits)) {
    return +V8_INFINITY;
  }
  for (size_t i = BoundariesSize() - 1; i-- > 0;) {
    if (Is(mins[i].internal, bits)) {
      return mz ? std::max(0.0, mins[i + 1].min - 1) : mins[i + 1].min - 1;
    }
  }
  DCHECK(mz);
  return 0;
}

// static
bool OtherNumberConstantType::IsOtherNumberConstant(double value) {
  // Not an integer, not NaN, and not -0.
  return !std::isnan(value) && !RangeType::IsInteger(value) &&
         !IsMinusZero(value);
}

HeapConstantType::HeapConstantType(BitsetType::bitset bitset,
                                   HeapObjectRef heap_ref)
    : TypeBase(kHeapConstant), bitset_(bitset), heap_ref_(heap_ref) {}

Handle<HeapObject> HeapConstantType::Value() const {
  return heap_ref_.object();
}

// -----------------------------------------------------------------------------
// Predicates.

bool Type::SimplyEquals(Type that) const {
  DisallowGarbageCollection no_gc;
  if (this->IsHeapConstant()) {
    return that.IsHeapConstant() &&
           this->AsHeapConstant()->Value().address() ==
               that.AsHeapConstant()->Value().address();
  }
  if (this->IsOtherNumberConstant()) {
    return that.IsOtherNumberConstant() &&
           this->AsOtherNumberConstant()->Value() ==
               that.AsOtherNumberConstant()->Value();
  }
  if (this->IsRange()) {
    if (that.IsHeapConstant() || that.IsOtherNumberConstant()) return false;
  }
  if (this->IsTuple()) {
    if (!that.IsTuple()) return false;
    const TupleType* this_tuple = this->AsTuple();
    const TupleType* that_tuple = that.AsTuple();
    if (this_tuple->Arity() != that_tuple->Arity()) {
      return false;
    }
    for (int i = 0, n = this_tuple->Arity(); i < n; ++i) {
      if (!this_tuple->Element(i).Equals(that_tuple->Element(i))) return false;
    }
    return true;
  }
  UNREACHABLE();
}

// Check if [this] <= [that].
bool Type::SlowIs(Type that) const {
  DisallowGarbageCollection no_gc;

  // Fast bitset cases
  if (that.IsBitset()) {
    return BitsetType::Is(this->BitsetLub(), that.AsBitset());
  }

  if (this->IsBitset()) {
    return BitsetType::Is(this->AsBitset(), that.BitsetGlb());
  }

  // (T1 \/ ... \/ Tn) <= T  if  (T1 <= T) /\ ... /\ (Tn <= T)
  if (this->IsUnion()) {
    for (int i = 0, n = this->AsUnion()->Length(); i < n; ++i) {
      if (!this->AsUnion()->Get(i).Is(that)) return false;
    }
    return true;
  }

  // T <= (T1 \/ ... \/ Tn)  if  (T <= T1) \/ ... \/ (T <= Tn)
  if (that.IsUnion()) {
    for (int i = 0, n = that.AsUnion()->Length(); i < n; ++i) {
      if (this->Is(that.AsUnion()->Get(i))) return true;
      if (i > 1 && this->IsRange()) return false;  // Shortcut.
    }
    return false;
  }

  if (that.IsRange()) {
    return this->IsRange() && Contains(that.AsRange(), this->AsRange());
  }
  if (this->IsRange()) return false;

#ifdef V8_ENABLE_WEBASSEMBLY
  if (this->IsWasm()) {
    if (!that.IsWasm()) return false;
    wasm::TypeInModule this_type = this->AsWasm();
    wasm::TypeInModule that_type = that.AsWasm();
    return wasm::IsSubtypeOf(this_type.type, that_type.type, this_type.module,
                             that_type.module);
  }
#endif

  return this->SimplyEquals(that);
}

// Check if [this] and [that] overlap.
bool Type::Maybe(Type that) const {
  DisallowGarbageCollection no_gc;

  if (BitsetType::IsNone(this->BitsetLub() & that.BitsetLub())) return false;

  // (T1 \/ ... \/ Tn) overlaps T  if  (T1 overlaps T) \/ ... \/ (Tn overlaps T)
  if (this->IsUnion()) {
    for (int i = 0, n = this->AsUnion()->Length(); i < n; ++i) {
      if (this->AsUnion()->Get(i).Maybe(that)) return true;
    }
    return false;
  }

  // T overlaps (T1 \/ ... \/ Tn)  if  (T overlaps T1) \/ ... \/ (T overlaps Tn)
  if (that.IsUnion()) {
    for (int i = 0, n = that.AsUnion()->Length(); i < n; ++i) {
      if (this->Maybe(that.AsUnion()->Get(i))) return true;
    }
    return false;
  }

  if (this->IsBitset() && that.IsBitset()) return true;

  if (this->IsRange()) {
    if (that.IsRange()) {
      return Overlap(this->AsRange(), that.AsRange());
    }
    if (that.IsBitset()) {
      bitset number_bits = BitsetType::NumberBits(that.AsBitset());
      if (number_bits == BitsetType::kNone) {
        return false;
      }
      double min = std::max(BitsetType::Min(number_bits), this->Min());
      double max = std::min(BitsetType::Max(number_bits), this->Max());
      return min <= max;
    }
  }
  if (that.IsRange()) {
    return that.Maybe(*this);  // This case is handled above.
  }

  if (this->IsBitset() || that.IsBitset()) return true;

  return this->SimplyEquals(that);
}

// Return the range in [this], or [nullptr].
Type Type::GetRange() const {
  DisallowGarbageCollection no_gc;
  if (this->IsRange()) return *this;
  if (this->IsUnion() && this->AsUnion()->Get(1).IsRange()) {
    return this->AsUnion()->Get(1);
  }
  return nullptr;
}

bool UnionType::Wellformed() const {
  DisallowGarbageCollection no_gc;
  // This checks the invariants of the union representation:
  // 1. There are at least two elements.
  // 2. The first element is a bitset, no other element is a bitset.
  // 3. At most one element is a range, and it must be the second one.
  // 4. No element is itself a union.
  // 5. No element (except the bitset) is a subtype of any other.
  // 6. If there is a range, then the bitset type does not contain
  //    plain number bits.
  DCHECK_LE(2, this->Length());     // (1)
  DCHECK(this->Get(0).IsBitset());  // (2a)

  for (int i = 0; i < this->Length(); ++i) {
    if (i != 0) DCHECK(!this->Get(i).IsBitset());  // (2b)
    if (i != 1) DCHECK(!this->Get(i).IsRange());   // (3)
    DCHECK(!this->Get(i).IsUnion());               // (4)
    for (int j = 0; j < this->Length(); ++j) {
      if (i != j && i != 0) DCHECK(!this->Get(i).Is(this->Get(j)));  // (5)
    }
  }
  DCHECK(!this->Get(1).IsRange() ||
         (BitsetType::NumberBits(this->Get(0).AsBitset()) ==
          BitsetType::kNone));  // (6)
  return true;
}

// -----------------------------------------------------------------------------
// Union and intersection

Type Type::Intersect(Type type1, Type type2, Zone* zone) {
  // Fast case: bit sets.
  if (type1.IsBitset() && type2.IsBitset()) {
    return NewBitset(type1.AsBitset() & type2.AsBitset());
  }

  // Fast case: top or bottom types.
  if (type1.IsNone() || type2.IsAny()) return type1;  // Shortcut.
  if (type2.IsNone() || type1.IsAny()) return type2;  // Shortcut.

  // Semi-fast case.
  if (type1.Is(type2)) return type1;
  if (type2.Is(type1)) return type2;

  // Slow case: create union.

  // Semantic subtyping check - this is needed for consistency with the
  // semi-fast case above.
  if (type1.Is(type2)) {
    type2 = Any();
  } else if (type2.Is(type1)) {
    type1 = Any();
  }

  bitset bits = type1.BitsetGlb() & type2.BitsetGlb();
  int size1 = type1.IsUnion() ? type1.AsUnion()->Length() : 1;
  int size2 = type2.IsUnion() ? type2.AsUnion()->Length() : 1;
  int size;
  if (base::bits::SignedAddOverflow32(size1, size2, &size)) return Any();
  if (base::bits::SignedAddOverflow32(size, 2, &size)) return Any();
  UnionType* result = UnionType::New(size, zone);
  size = 0;

  // Deal with bitsets.
  result->Set(size++, NewBitset(bits));

  RangeType::Limits lims = RangeType::Limits::Empty();
  size = IntersectAux(type1, type2, result, size, &lims, zone);

  // If the range is not empty, then insert it into the union and
  // remove the number bits from the bitset.
  if (!lims.IsEmpty()) {
    size = UpdateRange(Type::Range(lims, zone), result, size, zone);

    // Remove the number bits.
    bitset number_bits = BitsetType::NumberBits(bits);
    bits &= ~number_bits;
    result->Set(0, NewBitset(bits));
  }
  return NormalizeUnion(result, size, zone);
}

int Type::UpdateRange(Type range, UnionType* result, int size, Zone* zone) {
  if (size == 1) {
    result->Set(size++, range);
  } else {
    // Make space for the range.
    result->Set(size++, result->Get(1));
    result->Set(1, range);
  }

  // Remove any components that just got subsumed.
  for (int i = 2; i < size;) {
    if (result->Get(i).Is(range)) {
      result->Set(i, result->Get(--size));
    } else {
      ++i;
    }
  }
  return size;
}

RangeType::Limits Type::ToLimits(bitset bits, Zone* zone) {
  bitset number_bits = BitsetType::NumberBits(bits);

  if (number_bits == BitsetType::kNone) {
    return RangeType::Limits::Empty();
  }

  return RangeType::Limits(BitsetType::Min(number_bits),
                           BitsetType::Max(number_bits));
}

RangeType::Limits Type::IntersectRangeAndBitset(Type range, Type bitset,
                                                Zone* zone) {
  RangeType::Limits range_lims(range.AsRange());
  RangeType::Limits bitset_lims = ToLimits(bitset.AsBitset(), zone);
  return RangeType::Limits::Intersect(range_lims, bitset_lims);
}

int Type::IntersectAux(Type lhs, Type rhs, UnionType* result, int size,
                       RangeType::Limits* lims, Zone* zone) {
  if (lhs.IsUnion()) {
    for (int i = 0, n = lhs.AsUnion()->Length(); i < n; ++i) {
      size = IntersectAux(lhs.AsUnion()->Get(i), rhs, result, size, lims, zone);
    }
    return size;
  }
  if (rhs.IsUnion()) {
    for (int i = 0, n = rhs.AsUnion()->Length(); i < n; ++i) {
      size = IntersectAux(lhs, rhs.AsUnion()->Get(i), result, size, lims, zone);
    }
    return size;
  }

  if (BitsetType::IsNone(lhs.BitsetLub() & rhs.BitsetLub())) return size;

  if (lhs.IsRange()) {
    if (rhs.IsBitset()) {
      RangeType::Limits lim = IntersectRangeAndBitset(lhs, rhs, zone);

      if (!lim.IsEmpty()) {
        *lims = RangeType::Limits::Union(lim, *lims);
      }
      return size;
    }
    if (rhs.IsRange()) {
      RangeType::Limits lim = RangeType::Limits::Intersect(
          RangeType::Limits(lhs.AsRange()), RangeType::Limits(rhs.AsRange()));
      if (!lim.IsEmpty()) {
        *lims = RangeType::Limits::Union(lim, *lims);
      }
    }
    return size;
  }
  if (rhs.IsRange()) {
    // This case is handled symmetrically above.
    return IntersectAux(rhs, lhs, result, size, lims, zone);
  }
  if (lhs.IsBitset() || rhs.IsBitset()) {
    return AddToUnion(lhs.IsBitset() ? rhs : lhs, result, size, zone);
  }
  if (lhs.SimplyEquals(rhs)) {
    return AddToUnion(lhs, result, size, zone);
  }
  return size;
}

// Make sure that we produce a well-formed range and bitset:
// If the range is non-empty, the number bits in the bitset should be
// clear. Moreover, if we have a canonical range (such as Signed32),
// we want to produce a bitset rather than a range.
Type Type::NormalizeRangeAndBitset(Type range, bitset* bits, Zone* zone) {
  // Fast path: If the bitset does not mention numbers, we can just keep the
  // range.
  bitset number_bits = BitsetType::NumberBits(*bits);
  if (number_bits == 0) {
    return range;
  }

  // If the range is semantically contained within the bitset, return None and
  // leave the bitset untouched.
  bitset range_lub = range.BitsetLub();
  if (BitsetType::Is(range_lub, *bits)) {
    return None();
  }

  // Slow path: reconcile the bitset range and the range.
  double bitset_min = BitsetType::Min(number_bits);
  double bitset_max = BitsetType::Max(number_bits);

  double range_min = range.Min();
  double range_max = range.Max();

  // Remove the number bits from the bitset, they would just confuse us now.
  // NOTE: bits contains OtherNumber iff bits contains PlainNumber, in which
  // case we already returned after the subtype check above.
  *bits &= ~number_bits;

  if (range_min <= bitset_min && range_max >= bitset_max) {
    // Bitset is contained within the range, just return the range.
    return range;
  }

  if (bitset_min < range_min) {
    range_min = bitset_min;
  }
  if (bitset_max > range_max) {
    range_max = bitset_max;
  }
  return Type::Range(range_min, range_max, zone);
}

Type Type::Constant(double value, Zone* zone) {
  if (RangeType::IsInteger(value)) {
    return Range(value, value, zone);
  } else if (IsMinusZero(value)) {
    return Type::MinusZero();
  } else if (std::isnan(value)) {
    return Type::NaN();
  }

  DCHECK(OtherNumberConstantType::IsOtherNumberConstant(value));
  return OtherNumberConstant(value, zone);
}

Type Type::Constant(JSHeapBroker* broker, Handle<i::Object> value, Zone* zone) {
  // TODO(jgruber,chromium:1209798): Using kAssumeMemoryFence works around
  // the fact that the graph stores handles (and not refs). The assumption is
  // that any handle inserted into the graph is safe to read; but we don't
  // preserve the reason why it is safe to read. Thus we must over-approximate
  // here and assume the existence of a memory fence. In the future, we should
  // consider having the graph store ObjectRefs or ObjectData pointer instead,
  // which would make new ref construction here unnecessary.
  ObjectRef ref = MakeRefAssumeMemoryFence(broker, value);
  return Constant(broker, ref, zone);
}

Type Type::Constant(JSHeapBroker* broker, ObjectRef ref, Zone* zone) {
  if (ref.IsSmi()) {
    return Constant(static_cast<double>(ref.AsSmi()), zone);
  }
  if (ref.IsHeapNumber()) {
    return Constant(ref.AsHeapNumber().value(), zone);
  }
  if (ref.IsString() && !ref.IsInternalizedString()) {
    return Type::String();
  }
  if (ref.IsJSPrimitiveWrapper() &&
      ref.AsJSPrimitiveWrapper().IsStringWrapper(broker)) {
    return Type::StringWrapper();
  }
  if (ref.HoleType() != HoleType::kNone) {
    return Type::Hole();
  }
  return HeapConstant(ref.AsHeapObject(), broker, zone);
}

Type Type::Union(Type type1, Type type2, Zone* zone) {
  // Fast case: bit sets.
  if (type1.IsBitset() && type2.IsBitset()) {
    return NewBitset(type1.AsBitset() | type2.AsBitset());
  }

  // Fast case: top or bottom types.
  if (type1.IsAny() || type2.IsNone()) return type1;
  if (type2.IsAny() || type1.IsNone()) return type2;

  // Semi-fast case.
  if (type1.Is(type2)) return type2;
  if (type2.Is(type1)) return type1;

  // Slow case: create union.
  int size1 = type1.IsUnion() ? type1.AsUnion()->Length() : 1;
  int size2 = type2.IsUnion() ? type2.AsUnion()->Length() : 1;
  int size;
  if (base::bits::SignedAddOverflow32(size1, size2, &size)) return Any();
  if (base::bits::SignedAddOverflow32(size, 2, &size)) return Any();
  UnionType* result = UnionType::New(size, zone);
  size = 0;

  // Compute the new bitset.
  bitset new_bitset = type1.BitsetGlb() | type2.BitsetGlb();

  // Deal with ranges.
  Type range = None();
  Type range1 = type1.GetRange();
  Type range2 = type2.GetRange();
  if (range1 != nullptr && range2 != nullptr) {
    RangeType::Limits lims =
        RangeType::Limits::Union(RangeType::Limits(range1.AsRange()),
                                 RangeType::Limits(range2.AsRange()));
    Type union_range = Type::Range(lims, zone);
    range = NormalizeRangeAndBitset(union_range, &new_bitset, zone);
  } else if (range1 != nullptr) {
    range = NormalizeRangeAndBitset(range1, &new_bitset, zone);
  } else if (range2 != nullptr) {
    range = NormalizeRangeAndBitset(range2, &new_bitset, zone);
  }
  Type bits = NewBitset(new_bitset);
  result->Set(size++, bits);
  if (!range.IsNone()) result->Set(size++, range);

  size = AddToUnion(type1, result, size, zone);
  size = AddToUnion(type2, result, size, zone);
  return NormalizeUnion(result, size, zone);
}

// Add [type] to [result] unless [type] is bitset, range, or already subsumed.
// Return new size of [result].
int Type::AddToUnion(Type type, UnionType* result, int size, Zone* zone) {
  if (type.IsBitset() || type.IsRange()) return size;
  if (type.IsUnion()) {
    for (int i = 0, n = type.AsUnion()->Length(); i < n; ++i) {
      size = AddToUnion(type.AsUnion()->Get(i), result, size, zone);
    }
    return size;
  }
  for (int i = 0; i < size; ++i) {
    if (type.Is(result->Get(i))) return size;
  }
  result->Set(size++, type);
  return size;
}

Type Type::NormalizeUnion(UnionType* unioned, int size, Zone* zone) {
  DCHECK_LE(1, size);
  DCHECK(unioned->Get(0).IsBitset());
  // If the union has just one element, return it.
  if (size == 1) {
    return unioned->Get(0);
  }
  bitset bits = unioned->Get(0).AsBitset();
  // If the union only consists of a range, we can get rid of the union.
  if (size == 2 && bits == BitsetType::kNone) {
    if (unioned->Get(1).IsRange()) {
      return Type::Range(unioned->Get(1).AsRange()->Min(),
                         unioned->Get(1).AsRange()->Max(), zone);
    }
  }
  unioned->Shrink(size);
  SLOW_DCHECK(unioned->Wellformed());
  return Type(unioned);
}

int Type::NumConstants() const {
  DisallowGarbageCollection no_gc;
  if (this->IsHeapConstant() || this->IsOtherNumberConstant()) {
    return 1;
  } else if (this->IsUnion()) {
    int result = 0;
    for (int i = 0, n = this->AsUnion()->Length(); i < n; ++i) {
      if (this->AsUnion()->Get(i).IsHeapConstant()) ++result;
    }
    return result;
  } else {
    return 0;
  }
}

// -----------------------------------------------------------------------------
// Printing.

const char* BitsetType::Name(bitset bits) {
  switch (bits) {
#define RETURN_NAMED_TYPE(type, value) \
  case k##type:                        \
    return #type;
    PROPER_BITSET_TYPE_LIST(RETURN_NAMED_TYPE)
    INTERNAL_BITSET_TYPE_LIST(RETURN_NAMED_TYPE)
#undef RETURN_NAMED_TYPE

    default:
      return nullptr;
  }
}

void BitsetType::Print(std::ostream& os, bitset bits) {
  DisallowGarbageCollection no_gc;
  const char* name = Name(bits);
  if (name != nullptr) {
    os << name;
    return;
  }

  // clang-format off
  static const bitset named_bitsets[] = {
#define BITSET_CONSTANT(type, value) k##type,
    INTERNAL_BITSET_TYPE_LIST(BITSET_CONSTANT)
    PROPER_BITSET_TYPE_LIST(BITSET_CONSTANT)
#undef BITSET_CONSTANT
  };
  // clang-format on

  bool is_first = true;
  os << "(";
  for (int i(arraysize(named_bitsets) - 1); bits != 0 && i >= 0; --i) {
    bitset subset = named_bitsets[i];
    if ((bits & subset) == subset) {
      if (!is_first) os << " | ";
      is_first = false;
      os << Name(subset);
      bits -= subset;
    }
  }
  DCHECK_EQ(0, bits);
  os << ")";
}

void Type::PrintTo(std::ostream& os) const {
  DisallowGarbageCollection no_gc;
  if (this->IsBitset()) {
    BitsetType::Print(os, this->AsBitset());
  } else if (this->IsHeapConstant()) {
    os << "HeapConstant(" << this->AsHeapConstant()->Ref() << ")";
  } else if (this->IsOtherNumberConstant()) {
    os << "OtherNumberConstant(" << this->AsOtherNumberConstant()->Value()
       << ")";
  } else if (this->IsRange()) {
    std::ostream::fmtflags saved_flags = os.setf(std::ios::fixed);
    std::streamsize saved_precision = os.precision(0);
    os << "Range(" << this->AsRange()->Min() << ", " << this->AsRange()->Max()
       << ")";
    os.flags(saved_flags);
    os.precision(saved_precision);
  } else if (this->IsUnion()) {
    os << "(";
    for (int i = 0, n = this->AsUnion()->Length(); i < n; ++i) {
      Type type_i = this->AsUnion()->Get(i);
      if (i > 0) os << " | ";
      os << type_i;
    }
    os << ")";
  } else if (this->IsTuple()) {
    os << "<";
    for (int i = 0, n = this->AsTuple()->Arity(); i < n; ++i) {
      Type type_i = this->AsTuple()->Element(i);
      if (i > 0) os << ", ";
      os << type_i;
    }
    os << ">";
#ifdef V8_ENABLE_WEBASSEMBLY
  } else if (this->IsWasm()) {
    os << "Wasm:" << this->AsWasm().type.name();
#endif
  } else {
    UNREACHABLE();
  }
}

#ifdef DEBUG
void Type::Print() const {
  StdoutStream os;
  PrintTo(os);
  os << std::endl;
}
void BitsetType::Print(bitset bits) {
  StdoutStream os;
  Print(os, bits);
  os << std::endl;
}
#endif

BitsetType::bitset BitsetType::SignedSmall() {
  return SmiValuesAre31Bits() ? kSigned31 : kSigned32;
}

BitsetType::bitset BitsetType::UnsignedSmall() {
  return SmiValuesAre31Bits() ? kUnsigned30 : kUnsigned31;
}

// static
Type Type::Tuple(Type first, Type second, Type third, Zone* zone) {
  TupleType* tuple = TupleType::New(3, zone);
  tuple->InitElement(0, first);
  tuple->InitElement(1, second);
  tuple->InitElement(2, third);
  return FromTypeBase(tuple);
}

Type Type::Tuple(Type first, Type second, Zone* zone) {
  TupleType* tuple = TupleType::New(2, zone);
  tuple->InitElement(0, first);
  tuple->InitElement(1, second);
  return FromTypeBase(tuple);
}

// static
Type Type::OtherNumberConstant(double value, Zone* zone) {
  return FromTypeBase(OtherNumberConstantType::New(value, zone));
}

// static
Type Type::HeapConstant(HeapObjectRef value, JSHeapBroker* broker, Zone* zone) {
  DCHECK(!value.IsHeapNumber());
  DCHECK_EQ(value.HoleType(), HoleType::kNone);
  DCHECK_IMPLIES(value.IsString(), value.IsInternalizedString());
  BitsetType::bitset bitset =
      BitsetType::Lub(value.GetHeapObjectType(broker), broker);
  if (Type(bitset).IsSingleton()) return Type(bitset);
  return HeapConstantType::New(value, bitset, zone);
}

// static
Type Type::Range(double min, double max, Zone* zone) {
  return FromTypeBase(RangeType::New(min, max, zone));
}

// static
Type Type::Range(RangeType::Limits lims, Zone* zone) {
  return FromTypeBase(RangeType::New(lims, zone));
}

const HeapConstantType* Type::AsHeapConstant() const {
  DCHECK(IsKind(TypeBase::kHeapConstant));
  return static_cast<const HeapConstantType*>(ToTypeBase());
}

const OtherNumberConstantType* Type::AsOtherNumberConstant() const {
  DCHECK(IsKind(TypeBase::kOtherNumberConstant));
  return static_cast<const OtherNumberConstantType*>(ToTypeBase());
}

const RangeType* Type::AsRange() const {
  DCHECK(IsKind(TypeBase::kRange));
  return static_cast<const RangeType*>(ToTypeBase());
}

const TupleType* Type::AsTuple() const {
  DCHECK(IsKind(TypeBase::kTuple));
  return static_cast<const TupleType*>(ToTypeBase());
}

const UnionType* Type::AsUnion() const {
  DCHECK(IsKind(TypeBase::kUnion));
  return static_cast<const UnionType*>(ToTypeBase());
}

#ifdef V8_ENABLE_WEBASSEMBLY
// static
Type Type::Wasm(wasm::ValueType value_type, const wasm::WasmModule* module,
                Zone* zone) {
  return FromTypeBase(WasmType::New(value_type, module, zone));
}

// static
Type Type::Wasm(wasm::TypeInModule type_in_module, Zone* zone) {
  return Wasm(type_in_module.type, type_in_module.module, zone);
}

wasm::TypeInModule Type::AsWasm() const {
  DCHECK(IsKind(TypeBase::kWasm));
  auto wasm_type = static_cast<const WasmType*>(ToTypeBase());
  return {wasm_type->value_type(), wasm_type->module()};
}
#endif

std::ostream& operator<<(std::ostream& os, Type type) {
  type.PrintTo(os);
  return os;
}

Handle<TurbofanType> Type::AllocateOnHeap(Factory* factory) {
  DCHECK(CanBeAsserted());
  if (IsBitset()) {
    const bitset bits = AsBitset();
    uint32_t low = bits & 0xffffffff;
    uint32_t high = (bits >> 32) & 0xffffffff;
    return factory->NewTurbofanBitsetType(low, high, AllocationType::kYoung);
  } else if (IsUnion()) {
    const UnionType* union_type = AsUnion();
    Handle<TurbofanType> result = union_type->Get(0).AllocateOnHeap(factory);
    for (int i = 1; i < union_type->Length(); ++i) {
      result = factory->NewTurbofanUnionType(
          result, union_type->Get(i).AllocateOnHeap(factory),
          AllocationType::kYoung);
    }
    return result;
  } else if (IsHeapConstant()) {
    return factory->NewTurbofanHeapConstantType(AsHeapConstant()->Value(),
                                                AllocationType::kYoung);
  } else if (IsOtherNumberConstant()) {
    return factory->NewTurbofanOtherNumberConstantType(
        AsOtherNumberConstant()->Value(), AllocationType::kYoung);
  } else if (IsRange()) {
    return factory->NewTurbofanRangeType(AsRange()->Min(), AsRange()->Max(),
                                         AllocationType::kYoung);
  } else {
    // Other types are not supported for type assertions.
    UNREACHABLE();
  }
}

#define VERIFY_TORQUE_LOW_BITSET_AGREEMENT(Name, _)           \
  static_assert(static_cast<uint32_t>(BitsetType::k##Name) == \
                static_cast<uint32_t>(TurbofanTypeLowBits::k##Name));
#define VERIFY_TORQUE_HIGH_BITSET_AGREEMENT(Name, _)                     \
  static_assert(static_cast<uint32_t>(                                   \
                    static_cast<uint64_t>(BitsetType::k##Name) >> 32) == \
                static_cast<uint32_t>(TurbofanTypeHighBits::k##Name));
INTERNAL_BITSET_TYPE_LIST(VERIFY_TORQUE_LOW_BITSET_AGREEMENT)
PROPER_ATOMIC_BITSET_TYPE_LOW_LIST(VERIFY_TORQUE_LOW_BITSET_AGREEMENT)
PROPER_ATOMIC_BITSET_TYPE_HIGH_LIST(VERIFY_TORQUE_HIGH_BITSET_AGREEMENT)
#undef VERIFY_TORQUE_HIGH_BITSET_AGREEMENT
#undef VERIFY_TORQUE_LOW_BITSET_AGREEMENT

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```