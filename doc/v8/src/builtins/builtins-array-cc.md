Response:
Let's break down the thought process for analyzing the provided V8 C++ code snippet.

**1. Initial Scan and High-Level Understanding:**

* **Keywords:** The first thing I notice are keywords like `Copyright`, `#include`, `namespace v8::internal`, `BUILTIN`, `HandleScope`, `Handle<`, `Tagged<`, `JSArray`, `JSReceiver`, `Object`, etc. These immediately signal that it's V8 (JavaScript engine) C++ code, specifically dealing with built-in functions.
* **File Name:** The filename `builtins-array.cc` strongly suggests this code implements built-in methods for the JavaScript `Array` object.
* **Comments:**  The comments (e.g., "// Copyright...", "// 1. Let O be ...") are invaluable for understanding the intended logic and often directly correspond to the ECMAScript specification steps.
* **Focus:**  The presence of functions like `ArrayPrototypeFill`, `ArrayPush`, `ArrayPop`, `ArrayShift`, `ArrayUnshift` confirms the focus on standard array manipulation methods.

**2. Deeper Dive into Individual Functions (Pattern Recognition):**

* **`BUILTIN(FunctionName)`:**  This macro is the entry point for built-in functions. I recognize this pattern across multiple functions.
* **`HandleScope scope(isolate);`:** This is a common V8 idiom for managing memory and preventing leaks.
* **`Object::ToObject(isolate, args.receiver())`:**  This converts the `this` value to an object, a standard initial step in many array methods.
* **`GetLengthProperty(isolate, receiver)`:** This clearly retrieves the `length` property of an array-like object.
* **`GetRelativeIndex`, `SetLengthProperty`:** These are utility functions likely used for argument handling and length manipulation.
* **Generic vs. Fast Paths:** I see patterns like `EnsureJSArrayWithWritableFastElements` and calls to both generic (`GenericArrayFill`, `GenericArrayPush`, etc.) and potentially optimized (`accessor->Fill`, `accessor->Push`, etc.) implementations. This indicates V8 has performance optimizations for common array operations.
* **Error Handling:**  The use of `ASSIGN_RETURN_FAILURE_ON_EXCEPTION`, `MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION`, and `THROW_NEW_ERROR_RETURN_FAILURE` shows the code handles potential errors during the execution of array methods.
* **ECMAScript Steps:** Many comments directly map to the steps outlined in the ECMAScript specification for these array methods. This makes understanding the logic much easier.

**3. Identifying Key Concepts:**

* **Elements Kind:** The code mentions `ElementsKind` (e.g., `PACKED_ELEMENTS`, `HOLEY_ELEMENTS`, `DICTIONARY_ELEMENTS`). I know these represent different internal storage mechanisms for array elements, impacting performance.
* **Fast vs. Slow Paths:** The distinction between generic and fast implementations highlights V8's optimization strategies. Fast paths are used when certain conditions are met (e.g., simple elements, no accessors on the prototype chain).
* **Array-Like Objects:** The code works with `JSReceiver`, indicating it can operate on objects that resemble arrays (have a `length` property and indexed elements) even if they aren't true `JSArray` instances.
* **Prototype Chain:** Checks like `JSObject::PrototypeHasNoElements` suggest the code considers the impact of properties and accessors on the prototype chain.

**4. Answering the Specific Questions (Iterative Refinement):**

* **Functionality:** Based on the identified functions and patterns, I can list the main functionalities: `fill`, `push`, `pop`, `shift`, `unshift`.
* **Torque:** The prompt provides the information that a `.tq` extension indicates Torque. Since the file is `.cc`, it's C++.
* **JavaScript Examples:** I can translate the C++ logic into equivalent JavaScript code for each of the implemented built-in methods. This demonstrates the connection between the C++ implementation and the user-facing JavaScript API.
* **Logic Inference (Hypothetical Inputs/Outputs):** For functions like `ArrayPrototypeFill`, `ArrayPush`, `ArrayPop`, `ArrayShift`, I can create simple JavaScript examples and reason about their expected behavior based on the code. Focusing on the fast and slow paths helps illustrate how V8 might optimize.
* **Common Programming Errors:** I consider typical mistakes developers make when using these array methods (e.g., trying to `push` onto a non-extensible array, exceeding maximum array length). The error handling code in the C++ provides clues about potential issues.
* **Summary:**  Finally, I synthesize the information gathered to provide a concise summary of the file's purpose.

**Self-Correction/Refinement during the Process:**

* **Initial Assumption:**  I might initially assume *all* operations have a fast path. However, closer inspection reveals that certain conditions must be met. I'd refine my understanding accordingly.
* **Complexity of `EnsureJSArrayWithWritableFastElements`:**  The comments themselves point out the complexity. I recognize it as a crucial optimization check and focus on understanding its general purpose rather than getting bogged down in every detail of its implementation.
* **Focus on the "Why":**  Instead of just describing *what* the code does, I try to explain *why* certain checks or steps are present (e.g., why check for extensible arrays, why differentiate between elements kinds).

By following this structured approach, combining code analysis with domain knowledge about JavaScript and V8's architecture, I can effectively understand and summarize the functionality of the provided C++ source code.
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/logging.h"
#include "src/builtins/builtins-utils-inl.h"
#include "src/builtins/builtins.h"
#include "src/codegen/code-factory.h"
#include "src/common/assert-scope.h"
#include "src/debug/debug.h"
#include "src/execution/isolate.h"
#include "src/execution/protectors-inl.h"
#include "src/handles/global-handles-inl.h"
#include "src/logging/counters.h"
#include "src/objects/contexts.h"
#include "src/objects/elements-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/js-shared-array-inl.h"
#include "src/objects/lookup.h"
#include "src/objects/objects-inl.h"
#include "src/objects/prototype.h"
#include "src/objects/smi.h"

namespace v8 {
namespace internal {

namespace {

inline bool IsJSArrayFastElementMovingAllowed(Isolate* isolate,
                                              Tagged<JSArray> receiver) {
  return JSObject::PrototypeHasNoElements(isolate, receiver);
}

inline bool HasSimpleElements(Tagged<JSObject> current) {
  return !IsCustomElementsReceiverMap(current->map()) &&
         !current->GetElementsAccessor()->HasAccessors(current);
}

inline bool HasOnlySimpleReceiverElements(Isolate* isolate,
                                          Tagged<JSObject> receiver) {
  // Check that we have no accessors on the receiver's elements.
  if (!HasSimpleElements(receiver)) return false;
  return JSObject::PrototypeHasNoElements(isolate, receiver);
}

inline bool HasOnlySimpleElements(Isolate* isolate,
                                  Tagged<JSReceiver> receiver) {
  DisallowGarbageCollection no_gc;
  PrototypeIterator iter(isolate, receiver, kStartAtReceiver);
  for (; !iter.IsAtEnd(); iter.Advance()) {
    if (!IsJSObject(iter.GetCurrent())) return false;
    Tagged<JSObject> current = iter.GetCurrent<JSObject>();
    if (!HasSimpleElements(current)) return false;
  }
  return true;
}

// This method may transition the elements kind of the JSArray once, to make
// sure that all elements provided as arguments in the specified range can be
// added without further elements kinds transitions.
void MatchArrayElementsKindToArguments(Isolate* isolate, Handle<JSArray> array,
                                       BuiltinArguments* args,
                                       int first_arg_index, int num_arguments) {
  int args_length = args->length();
  if (first_arg_index >= args_length) return;

  ElementsKind origin_kind = array->GetElementsKind();

  // We do not need to transition for PACKED/HOLEY_ELEMENTS.
  if (IsObjectElementsKind(origin_kind)) return;

  ElementsKind target_kind = origin_kind;
  {
    DisallowGarbageCollection no_gc;
    int last_arg_index = std::min(first_arg_index + num_arguments, args_length);
    for (int i = first_arg_index; i < last_arg_index; i++) {
      Tagged<Object> arg = (*args)[i];
      if (IsHeapObject(arg)) {
        if (IsHeapNumber(arg)) {
          target_kind = PACKED_DOUBLE_ELEMENTS;
        } else {
          target_kind = PACKED_ELEMENTS;
          break;
        }
      }
    }
  }
  if (target_kind != origin_kind) {
    // Use a short-lived HandleScope to avoid creating several copies of the
    // elements handle which would cause issues when left-trimming later-on.
    HandleScope scope(isolate);
    JSObject::TransitionElementsKind(array, target_kind);
  }
}

// Returns |false| if not applicable.
// TODO(szuend): Refactor this function because it is getting hard to
//               understand what each call-site actually checks.
V8_WARN_UNUSED_RESULT
inline bool EnsureJSArrayWithWritableFastElements(Isolate* isolate,
                                                  Handle<Object> receiver,
                                                  BuiltinArguments* args,
                                                  int first_arg_index,
                                                  int num_arguments) {
  if (!IsJSArray(*receiver)) return false;
  Handle<JSArray> array = Cast<JSArray>(receiver);
  ElementsKind origin_kind = array->GetElementsKind();
  if (IsDictionaryElementsKind(origin_kind)) return false;
  if (!array->map()->is_extensible()) return false;
  if (args == nullptr) return true;

  // If there may be elements accessors in the prototype chain, the fast path
  // cannot be used if there arguments to add to the array.
  if (!IsJSArrayFastElementMovingAllowed(isolate, *array)) return false;

  // Adding elements to the array prototype would break code that makes sure
  // it has no elements. Handle that elsewhere.
  if (isolate->IsInitialArrayPrototype(*array)) return false;

  // Need to ensure that the arguments passed in args can be contained in
  // the array.
  MatchArrayElementsKindToArguments(isolate, array, args, first_arg_index,
                                    num_arguments);
  return true;
}

// If |index| is Undefined, returns init_if_undefined.
// If |index| is negative, returns length + index.
// If |index| is positive, returns index.
// Returned value is guaranteed to be in the interval of [0, length].
V8_WARN_UNUSED_RESULT Maybe<double> GetRelativeIndex(Isolate* isolate,
                                                     double length,
                                                     Handle<Object> index,
                                                     double init_if_undefined) {
  double relative_index = init_if_undefined;
  if (!IsUndefined(*index)) {
    Handle<Object> relative_index_obj;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, relative_index_obj,
                                     Object::ToInteger(isolate, index),
                                     Nothing<double>());
    relative_index = Object::NumberValue(*relative_index_obj);
  }

  if (relative_index < 0) {
    return Just(std::max(length + relative_index, 0.0));
  }

  return Just(std::min(relative_index, length));
}

// Returns "length", has "fast-path" for JSArrays.
V8_WARN_UNUSED_RESULT Maybe<double> GetLengthProperty(
    Isolate* isolate, Handle<JSReceiver> receiver) {
  if (IsJSArray(*receiver)) {
    auto array = Cast<JSArray>(receiver);
    double length = Object::NumberValue(array->length());
    DCHECK(0 <= length && length <= kMaxSafeInteger);

    return Just(length);
  }

  Handle<Object> raw_length_number;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, raw_length_number,
      Object::GetLengthFromArrayLike(isolate, receiver), Nothing<double>());
  return Just(Object::NumberValue(*raw_length_number));
}

// Set "length" property, has "fast-path" for JSArrays.
// Returns Nothing if something went wrong.
V8_WARN_UNUSED_RESULT MaybeHandle<Object> SetLengthProperty(
    Isolate* isolate, Handle<JSReceiver> receiver, double length) {
  if (IsJSArray(*receiver)) {
    Handle<JSArray> array = Cast<JSArray>(receiver);
    if (!JSArray::HasReadOnlyLength(array)) {
      DCHECK_LE(length, kMaxUInt32);
      MAYBE_RETURN_NULL(
          JSArray::SetLength(array, static_cast<uint32_t>(length)));
      return receiver;
    }
  }

  return Object::SetProperty(
      isolate, receiver, isolate->factory()->length_string(),
      isolate->factory()->NewNumber(length), StoreOrigin::kMaybeKeyed,
      Just(ShouldThrow::kThrowOnError));
}

V8_WARN_UNUSED_RESULT Tagged<Object> GenericArrayFill(
    Isolate* isolate, Handle<JSReceiver> receiver, Handle<Object> value,
    double start, double end) {
  // 7. Repeat, while k < final.
  while (start < end) {
    // a. Let Pk be ! ToString(k).
    Handle<String> index = isolate->factory()->NumberToString(
        isolate->factory()->NewNumber(start));

    // b. Perform ? Set(O, Pk, value, true).
    RETURN_FAILURE_ON_EXCEPTION(isolate, Object::SetPropertyOrElement(
                                             isolate, receiver, index, value,
                                             Just(ShouldThrow::kThrowOnError)));

    // c. Increase k by 1.
    ++start;
  }

  // 8. Return O.
  return *receiver;
}

V8_WARN_UNUSED_RESULT Maybe<bool> TryFastArrayFill(
    Isolate* isolate, BuiltinArguments* args, Handle<JSReceiver> receiver,
    Handle<Object> value, double start_index, double end_index) {
  // If indices are too large, use generic path since they are stored as
  // properties, not in the element backing store.
  if (end_index > kMaxUInt32) return Just(false);
  if (!IsJSObject(*receiver)) return Just(false);

  if (!EnsureJSArrayWithWritableFastElements(isolate, receiver, args, 1, 1)) {
    return Just(false);
  }

  Handle<JSArray> array = Cast<JSArray>(receiver);

  // If no argument was provided, we fill the array with 'undefined'.
  // EnsureJSArrayWith... does not handle that case so we do it here.
  // TODO(szuend): Pass target elements kind to EnsureJSArrayWith... when
  //               it gets refactored.
  if (args->length() == 1 && array->GetElementsKind() != PACKED_ELEMENTS) {
    // Use a short-lived HandleScope to avoid creating several copies of the
    // elements handle which would cause issues when left-trimming later-on.
    HandleScope scope(isolate);
    JSObject::TransitionElementsKind(array, PACKED_ELEMENTS);
  }

  DCHECK_LE(start_index, kMaxUInt32);
  DCHECK_LE(end_index, kMaxUInt32);

  uint32_t start, end;
  CHECK(DoubleToUint32IfEqualToSelf(start_index, &start));
  CHECK(DoubleToUint32IfEqualToSelf(end_index, &end));

  ElementsAccessor* accessor = array->GetElementsAccessor();
  RETURN_ON_EXCEPTION_VALUE(isolate, accessor->Fill(array, value, start, end),
                            Nothing<bool>());

  // It's possible the JSArray's 'length' property was assigned to after the
  // length was loaded due to user code during argument coercion of the start
  // and end parameters. The spec algorithm does a Set, meaning the length would
  // grow as needed during the fill.
  //
  // ElementAccessor::Fill is able to grow the backing store as needed, but we
  // need to ensure the JSArray's length is correctly set in case the user
  // assigned a smaller value.
  if (Object::NumberValue(array->length()) < end) {
    CHECK(accessor->SetLength(array, end).FromJust());
  }

  return Just(true);
}
}  // namespace

BUILTIN(ArrayPrototypeFill) {
  HandleScope scope(isolate);

  // 1. Let O be ? ToObject(this value).
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, receiver, Object::ToObject(isolate, args.receiver()));

  // 2. Let len be ? ToLength(? Get(O, "length")).
  double length;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, length, GetLengthProperty(isolate, receiver));

  // 3. Let relativeStart be ? ToInteger(start).
  // 4. If relativeStart < 0, let k be max((len + relativeStart), 0);
  //    else let k be min(relativeStart, len).
  Handle<Object> start = args.atOrUndefined(isolate, 2);

  double start_index;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, start_index, GetRelativeIndex(isolate, length, start, 0));

  // 5. If end is undefined, let relativeEnd be len;
  //    else let relativeEnd be ? ToInteger(end).
  // 6. If relativeEnd < 0, let final be max((len + relativeEnd), 0);
  //    else let final be min(relativeEnd, len).
  Handle<Object> end = args.atOrUndefined(isolate, 3);

  double end_index;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, end_index, GetRelativeIndex(isolate, length, end, length));

  if (start_index >= end_index) return *receiver;

  // Ensure indexes are within array bounds
  DCHECK_LE(0, start_index);
  DCHECK_LE(start_index, end_index);
  DCHECK_LE(end_index, length);

  Handle<Object> value = args.atOrUndefined(isolate, 1);

  bool success;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, success,
      TryFastArrayFill(isolate, &args, receiver, value, start_index,
                       end_index));
  if (success) return *receiver;
  return GenericArrayFill(isolate, receiver, value, start_index, end_index);
}

namespace {
V8_WARN_UNUSED_RESULT Tagged<Object> GenericArrayPush(Isolate* isolate,
                                                      BuiltinArguments* args) {
  // 1. Let O be ? ToObject(this value).
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, receiver, Object::ToObject(isolate, args->receiver()));

  // 2. Let len be ? ToLength(? Get(O, "length")).
  Handle<Object> raw_length_number;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, raw_length_number,
      Object::GetLengthFromArrayLike(isolate, receiver));

  // 3. Let args be a List whose elements are, in left to right order,
  //    the arguments that were passed to this function invocation.
  // 4. Let arg_count be the number of elements in args.
  int arg_count = args->length() - 1;

  // 5. If len + arg_count > 2^53-1, throw a TypeError exception.
  double length = Object::NumberValue(*raw_length_number);
  if (arg_count > kMaxSafeInteger - length) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kPushPastSafeLength,
                              isolate->factory()->NewNumberFromInt(arg_count),
                              raw_length_number));
  }

  // 6. Repeat, while args is not empty.
  for (int i = 0; i < arg_count; ++i) {
    // a. Remove the first element from args and let E be the value of the
    //    element.
    Handle<Object> element = args->at(i + 1);

    // b. Perform ? Set(O, ! ToString(len), E, true).
    if (length <= JSObject::kMaxElementIndex) {
      RETURN_FAILURE_ON_EXCEPTION(
          isolate, Object::SetElement(isolate, receiver, length, element,
                                      ShouldThrow::kThrowOnError));
    } else {
      PropertyKey key(isolate, length);
      LookupIterator it(isolate, receiver, key);
      MAYBE_RETURN(Object::SetProperty(&it, element, StoreOrigin::kMaybeKeyed,
                                       Just(ShouldThrow::kThrowOnError)),
                   ReadOnlyRoots(isolate).exception());
    }

    // c. Let len be len+1.
    ++length;
  }

  // 7. Perform ? Set(O, "length", len, true).
  Handle<Object> final_length = isolate->factory()->NewNumber(length);
  RETURN_FAILURE_ON_EXCEPTION(
      isolate, Object::SetProperty(isolate, receiver,
                                   isolate->factory()->length_string(),
                                   final_length, StoreOrigin::kMaybeKeyed,
                                   Just(ShouldThrow::kThrowOnError)));

  // 8. Return len.
  return *final_length;
}
}  // namespace

BUILTIN(ArrayPush) {
  HandleScope scope(isolate);
  Handle<Object> receiver = args.receiver();
  if (!EnsureJSArrayWithWritableFastElements(isolate, receiver, &args, 1,
                                             args.length() - 1)) {
    return GenericArrayPush(isolate, &args);
  }

  Handle<JSArray> array = Cast<JSArray>(receiver);
  bool has_read_only_length = JSArray::HasReadOnlyLength(array);

  if (has_read_only_length) {
    return GenericArrayPush(isolate, &args);
  }

  // Fast Elements Path
  int to_add = args.length() - 1;
  uint32_t len = static_cast<uint32_t>(Object::NumberValue(array->length()));
  if (to_add == 0) return *isolate->factory()->NewNumberFromUint(len);

  // Currently fixed arrays cannot grow too big, so we should never hit this.
  DCHECK_LE(to_add, Smi::kMaxValue - Smi::ToInt(array->length()));

  ElementsAccessor* accessor = array->GetElementsAccessor();
  uint32_t new_length;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, new_length, accessor->Push(array, &args, to_add));
  return *isolate->factory()->NewNumberFromUint((new_length));
}

namespace {

V8_WARN_UNUSED_RESULT Tagged<Object> GenericArrayPop(Isolate* isolate,
                                                     BuiltinArguments* args) {
  // 1. Let O be ? ToObject(this value).
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, receiver, Object::ToObject(isolate, args->receiver()));

  // 2. Let len be ? ToLength(? Get(O, "length")).
  Handle<Object> raw_length_number;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, raw_length_number,
      Object::GetLengthFromArrayLike(isolate, receiver));
  double length = Object::NumberValue(*raw_length_number);

  // 3. If len is zero, then.
  if (length == 0) {
    // a. Perform ? Set(O, "length", 0, true).
    RETURN_FAILURE_ON_EXCEPTION(
        isolate, Object::SetProperty(isolate, receiver,
                                     isolate->factory()->length_string(),
                                     Handle<Smi>(Smi::zero(), isolate),
                                     StoreOrigin::kMaybeKeyed,
                                     Just(ShouldThrow::kThrowOnError)));

    // b. Return undefined.
    return ReadOnlyRoots(isolate).undefined_value();
  }

  // 4. Else len > 0.
  // a. Let new_len be len-1.
  Handle<Object> new_length = isolate->factory()->NewNumber(length - 1);

  // b. Let index be ! ToString(newLen).
  Handle<String> index = isolate->factory()->NumberToString(new_length);

  // c. Let element be ? Get(O, index).
  Handle<Object> element;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, element, Object::GetPropertyOrElement(isolate, receiver, index));

  // d. Perform ? DeletePropertyOrThrow(O, index).
  MAYBE_RETURN(JSReceiver::DeletePropertyOrElement(isolate, receiver, index,
                                                   LanguageMode::kStrict),
               ReadOnlyRoots(isolate).exception());

  // e. Perform ? Set(O, "length", newLen, true).
  RETURN_FAILURE_ON_EXCEPTION(
      isolate, Object::SetProperty(isolate, receiver,
                                   isolate->factory()->length_string(),
                                   new_length, StoreOrigin::kMaybeKeyed,
                                   Just(ShouldThrow::kThrowOnError)));

  // f. Return element.
  return *element;
}

}  // namespace

BUILTIN(ArrayPop) {
  HandleScope scope(isolate);
  Handle<Object> receiver = args.receiver();
  if (!EnsureJSArrayWithWritableFastElements(isolate, receiver, nullptr, 0,
                                             0)) {
    return GenericArrayPop(isolate, &args);
  }
  Handle<JSArray> array = Cast<JSArray>(receiver);

  uint32_t len = static_cast<uint32_t>(Object::NumberValue(array->length()));

  if (JSArray::HasReadOnlyLength(array)) {
    return GenericArrayPop(isolate, &args);
  }
  if (len == 0) return ReadOnlyRoots(isolate).undefined_value();

  Handle<Object> result;
  if (IsJSArrayFastElementMovingAllowed(isolate, Cast<JSArray>(*receiver))) {
    // Fast Elements Path
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, result, array->GetElementsAccessor()->Pop(array));
  } else {
    // Use Slow Lookup otherwise
    uint32_t new_length = len - 1;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, result, JSReceiver::GetElement(isolate, array, new_length));

    // The length could have become read-only during the last GetElement() call,
    // so check again.
    if (JSArray::HasReadOnlyLength(array)) {
      THROW_NEW_ERROR_RETURN_FAILURE(
          isolate, NewTypeError(MessageTemplate::kStrictReadOnlyProperty,
                                isolate->factory()->length_string(),
                                Object::TypeOf(isolate, array), array));
    }
    bool set_len_ok;
    MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, set_len_ok, JSArray::SetLength(array, new_length));
  }

  return *result;
}

namespace {

// Returns true, iff we can use ElementsAccessor for shifting.
V8_WARN_UNUSED_RESULT bool CanUseFastArrayShift(Isolate* isolate,
                                                Handle<JSReceiver> receiver) {
  if (V8_COMPRESS_POINTERS_8GB_BOOL) return false;

  if (!EnsureJSArrayWithWritableFastElements(isolate, receiver, nullptr, 0,
                                             0) ||
      !IsJSArrayFastElementMovingAllowed(isolate, Cast<JSArray>(*receiver))) {
    return false;
  }

  Handle<JSArray> array = Cast<JSArray>(receiver);
  return !JSArray::HasReadOnlyLength(array);
}

V8_WARN_UNUSED_RESULT Tagged<Object> GenericArrayShift(
    Isolate* isolate, Handle<JSReceiver> receiver, double length) {
  // 4. Let first be ? Get(O, "0").
  Handle<Object> first;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, first,
                                     Object::GetElement(isolate, receiver, 0));

  // 5. Let k be 1.
  double k = 1;

  // 6. Repeat, while k < len.
  while (k < length) {
    // a. Let from be ! ToString(k).
    Handle<String> from =
        isolate->factory()->NumberToString(isolate->factory()->NewNumber(k));

    // b. Let to be ! ToString(k-1).
    Handle<String> to = isolate->factory()->NumberToString(
        isolate->factory()->NewNumber(k - 1));

    // c. Let fromPresent be ? HasProperty(O, from).
    bool from_present;
    MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, from_present,
        JSReceiver::HasProperty(isolate, receiver, from));

    // d. If fromPresent is true, then.
    if (from_present) {
      // i. Let fromVal be ? Get(O, from).
      Handle<Object> from_val;
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
          isolate, from_val,
          Object::GetPropertyOrElement(isolate, receiver, from));

      // ii. Perform ? Set(O, to, fromVal, true).
      RETURN_FAILURE_ON_EXCEPTION(
          isolate,
          Object::SetPropertyOrElement(isolate, receiver, to, from_val,
                                       Just(ShouldThrow::kThrowOnError)));
    } else {  // e. Else fromPresent is false,
      // i. Perform ? DeletePropertyOrThrow(O, to).
      MAYBE_RETURN(JSReceiver::DeletePropertyOrElement(isolate, receiver, to,
                                                       LanguageMode::kStrict),
                   ReadOnlyRoots(isolate).exception());
    }

    // f. Increase k by 1.
    ++k;
  }

  // 7. Perform ? DeletePropertyOrThrow(O, ! ToString(len-1)).
  Handle<String> new_length = isolate->factory()->NumberToString(
      isolate->factory()->NewNumber(length - 1));
  MAYBE_RETURN(JSReceiver::DeletePropertyOrElement(
                   isolate, receiver, new_length, LanguageMode::kStrict),
               ReadOnlyRoots(isolate).exception());

  // 8. Perform ? Set(O, "length", len-1, true).
  RETURN_FAILURE_ON_EXCEPTION(isolate,
                              SetLengthProperty(isolate, receiver, length - 1));

  // 9. Return first.
  return *first;
}
}  // namespace

BUILTIN(ArrayShift) {
  HandleScope scope(isolate);

  // 1. Let O be ? ToObject(this value).
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, receiver, Object::ToObject(isolate, args.receiver()));

  // 2. Let len be ? ToLength(? Get(O, "length")).
  double length;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, length, GetLengthProperty(isolate, receiver));

  // 3. If len is zero, then.
  if (length == 0) {
    // a. Perform ? Set(O, "length", 0, true).
    RETURN_FAILURE_ON_EXCEPTION(isolate,
                                SetLengthProperty(isolate, receiver, length));

    // b. Return undefined.
    return ReadOnlyRoots(isolate).undefined_value();
  }

  if (CanUseFastArrayShift(isolate, receiver)) {
    Handle<JSArray> array = Cast<JSArray>(receiver);
    RETURN_RESULT_OR_FAILURE(isolate,
                             array->GetElementsAccessor()->Shift(array));
  }

  return GenericArrayShift(isolate, receiver, length);
}

BUILTIN(ArrayUnshift) {
  HandleScope scope(isolate);
  DCHECK(IsJSArray(*args.receiver()));
  Handle<JSArray> array = Cast<JSArray>(args.receiver());

  // These are checked in the Torque builtin.
  DCHECK(array->map()->is_extensible());
  DCHECK(!IsDictionaryElementsKind(array->GetElementsKind()));
  DCHECK(IsJSArrayFastElementMovingAllowed(isolate, *array));
  DCHECK(!isolate->IsInitialArrayPrototype(*array));

  MatchArrayElementsKindToArguments(isolate, array, &args, 1,
                                    args.length() - 1);

  int to_add = args.length() - 1;
  if (to_add == 0) return array->length();

  // Currently fixed arrays cannot grow too big, so we should never hit this.
  DCHECK_LE(to_add, Smi::kMaxValue - Smi::ToInt(array->length()));
  DCHECK(!JSArray::HasReadOnlyLength(array));

  ElementsAccessor* accessor = array->GetElementsAccessor();
  uint32_t new_length;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, new_length, accessor->Unshift(array, &args, to_add));
  return Smi::FromInt(new_length);
}

// Array Concat -------------------------------------------------------------

namespace {

/**
 * A simple visitor visits every element of Array's.
 * The backend storage can be a fixed array for fast elements case,
 * or a
### 提示词
```
这是目录为v8/src/builtins/builtins-array.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-array.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/logging.h"
#include "src/builtins/builtins-utils-inl.h"
#include "src/builtins/builtins.h"
#include "src/codegen/code-factory.h"
#include "src/common/assert-scope.h"
#include "src/debug/debug.h"
#include "src/execution/isolate.h"
#include "src/execution/protectors-inl.h"
#include "src/handles/global-handles-inl.h"
#include "src/logging/counters.h"
#include "src/objects/contexts.h"
#include "src/objects/elements-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/js-shared-array-inl.h"
#include "src/objects/lookup.h"
#include "src/objects/objects-inl.h"
#include "src/objects/prototype.h"
#include "src/objects/smi.h"

namespace v8 {
namespace internal {

namespace {

inline bool IsJSArrayFastElementMovingAllowed(Isolate* isolate,
                                              Tagged<JSArray> receiver) {
  return JSObject::PrototypeHasNoElements(isolate, receiver);
}

inline bool HasSimpleElements(Tagged<JSObject> current) {
  return !IsCustomElementsReceiverMap(current->map()) &&
         !current->GetElementsAccessor()->HasAccessors(current);
}

inline bool HasOnlySimpleReceiverElements(Isolate* isolate,
                                          Tagged<JSObject> receiver) {
  // Check that we have no accessors on the receiver's elements.
  if (!HasSimpleElements(receiver)) return false;
  return JSObject::PrototypeHasNoElements(isolate, receiver);
}

inline bool HasOnlySimpleElements(Isolate* isolate,
                                  Tagged<JSReceiver> receiver) {
  DisallowGarbageCollection no_gc;
  PrototypeIterator iter(isolate, receiver, kStartAtReceiver);
  for (; !iter.IsAtEnd(); iter.Advance()) {
    if (!IsJSObject(iter.GetCurrent())) return false;
    Tagged<JSObject> current = iter.GetCurrent<JSObject>();
    if (!HasSimpleElements(current)) return false;
  }
  return true;
}

// This method may transition the elements kind of the JSArray once, to make
// sure that all elements provided as arguments in the specified range can be
// added without further elements kinds transitions.
void MatchArrayElementsKindToArguments(Isolate* isolate, Handle<JSArray> array,
                                       BuiltinArguments* args,
                                       int first_arg_index, int num_arguments) {
  int args_length = args->length();
  if (first_arg_index >= args_length) return;

  ElementsKind origin_kind = array->GetElementsKind();

  // We do not need to transition for PACKED/HOLEY_ELEMENTS.
  if (IsObjectElementsKind(origin_kind)) return;

  ElementsKind target_kind = origin_kind;
  {
    DisallowGarbageCollection no_gc;
    int last_arg_index = std::min(first_arg_index + num_arguments, args_length);
    for (int i = first_arg_index; i < last_arg_index; i++) {
      Tagged<Object> arg = (*args)[i];
      if (IsHeapObject(arg)) {
        if (IsHeapNumber(arg)) {
          target_kind = PACKED_DOUBLE_ELEMENTS;
        } else {
          target_kind = PACKED_ELEMENTS;
          break;
        }
      }
    }
  }
  if (target_kind != origin_kind) {
    // Use a short-lived HandleScope to avoid creating several copies of the
    // elements handle which would cause issues when left-trimming later-on.
    HandleScope scope(isolate);
    JSObject::TransitionElementsKind(array, target_kind);
  }
}

// Returns |false| if not applicable.
// TODO(szuend): Refactor this function because it is getting hard to
//               understand what each call-site actually checks.
V8_WARN_UNUSED_RESULT
inline bool EnsureJSArrayWithWritableFastElements(Isolate* isolate,
                                                  Handle<Object> receiver,
                                                  BuiltinArguments* args,
                                                  int first_arg_index,
                                                  int num_arguments) {
  if (!IsJSArray(*receiver)) return false;
  Handle<JSArray> array = Cast<JSArray>(receiver);
  ElementsKind origin_kind = array->GetElementsKind();
  if (IsDictionaryElementsKind(origin_kind)) return false;
  if (!array->map()->is_extensible()) return false;
  if (args == nullptr) return true;

  // If there may be elements accessors in the prototype chain, the fast path
  // cannot be used if there arguments to add to the array.
  if (!IsJSArrayFastElementMovingAllowed(isolate, *array)) return false;

  // Adding elements to the array prototype would break code that makes sure
  // it has no elements. Handle that elsewhere.
  if (isolate->IsInitialArrayPrototype(*array)) return false;

  // Need to ensure that the arguments passed in args can be contained in
  // the array.
  MatchArrayElementsKindToArguments(isolate, array, args, first_arg_index,
                                    num_arguments);
  return true;
}

// If |index| is Undefined, returns init_if_undefined.
// If |index| is negative, returns length + index.
// If |index| is positive, returns index.
// Returned value is guaranteed to be in the interval of [0, length].
V8_WARN_UNUSED_RESULT Maybe<double> GetRelativeIndex(Isolate* isolate,
                                                     double length,
                                                     Handle<Object> index,
                                                     double init_if_undefined) {
  double relative_index = init_if_undefined;
  if (!IsUndefined(*index)) {
    Handle<Object> relative_index_obj;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, relative_index_obj,
                                     Object::ToInteger(isolate, index),
                                     Nothing<double>());
    relative_index = Object::NumberValue(*relative_index_obj);
  }

  if (relative_index < 0) {
    return Just(std::max(length + relative_index, 0.0));
  }

  return Just(std::min(relative_index, length));
}

// Returns "length", has "fast-path" for JSArrays.
V8_WARN_UNUSED_RESULT Maybe<double> GetLengthProperty(
    Isolate* isolate, Handle<JSReceiver> receiver) {
  if (IsJSArray(*receiver)) {
    auto array = Cast<JSArray>(receiver);
    double length = Object::NumberValue(array->length());
    DCHECK(0 <= length && length <= kMaxSafeInteger);

    return Just(length);
  }

  Handle<Object> raw_length_number;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, raw_length_number,
      Object::GetLengthFromArrayLike(isolate, receiver), Nothing<double>());
  return Just(Object::NumberValue(*raw_length_number));
}

// Set "length" property, has "fast-path" for JSArrays.
// Returns Nothing if something went wrong.
V8_WARN_UNUSED_RESULT MaybeHandle<Object> SetLengthProperty(
    Isolate* isolate, Handle<JSReceiver> receiver, double length) {
  if (IsJSArray(*receiver)) {
    Handle<JSArray> array = Cast<JSArray>(receiver);
    if (!JSArray::HasReadOnlyLength(array)) {
      DCHECK_LE(length, kMaxUInt32);
      MAYBE_RETURN_NULL(
          JSArray::SetLength(array, static_cast<uint32_t>(length)));
      return receiver;
    }
  }

  return Object::SetProperty(
      isolate, receiver, isolate->factory()->length_string(),
      isolate->factory()->NewNumber(length), StoreOrigin::kMaybeKeyed,
      Just(ShouldThrow::kThrowOnError));
}

V8_WARN_UNUSED_RESULT Tagged<Object> GenericArrayFill(
    Isolate* isolate, Handle<JSReceiver> receiver, Handle<Object> value,
    double start, double end) {
  // 7. Repeat, while k < final.
  while (start < end) {
    // a. Let Pk be ! ToString(k).
    Handle<String> index = isolate->factory()->NumberToString(
        isolate->factory()->NewNumber(start));

    // b. Perform ? Set(O, Pk, value, true).
    RETURN_FAILURE_ON_EXCEPTION(isolate, Object::SetPropertyOrElement(
                                             isolate, receiver, index, value,
                                             Just(ShouldThrow::kThrowOnError)));

    // c. Increase k by 1.
    ++start;
  }

  // 8. Return O.
  return *receiver;
}

V8_WARN_UNUSED_RESULT Maybe<bool> TryFastArrayFill(
    Isolate* isolate, BuiltinArguments* args, Handle<JSReceiver> receiver,
    Handle<Object> value, double start_index, double end_index) {
  // If indices are too large, use generic path since they are stored as
  // properties, not in the element backing store.
  if (end_index > kMaxUInt32) return Just(false);
  if (!IsJSObject(*receiver)) return Just(false);

  if (!EnsureJSArrayWithWritableFastElements(isolate, receiver, args, 1, 1)) {
    return Just(false);
  }

  Handle<JSArray> array = Cast<JSArray>(receiver);

  // If no argument was provided, we fill the array with 'undefined'.
  // EnsureJSArrayWith... does not handle that case so we do it here.
  // TODO(szuend): Pass target elements kind to EnsureJSArrayWith... when
  //               it gets refactored.
  if (args->length() == 1 && array->GetElementsKind() != PACKED_ELEMENTS) {
    // Use a short-lived HandleScope to avoid creating several copies of the
    // elements handle which would cause issues when left-trimming later-on.
    HandleScope scope(isolate);
    JSObject::TransitionElementsKind(array, PACKED_ELEMENTS);
  }

  DCHECK_LE(start_index, kMaxUInt32);
  DCHECK_LE(end_index, kMaxUInt32);

  uint32_t start, end;
  CHECK(DoubleToUint32IfEqualToSelf(start_index, &start));
  CHECK(DoubleToUint32IfEqualToSelf(end_index, &end));

  ElementsAccessor* accessor = array->GetElementsAccessor();
  RETURN_ON_EXCEPTION_VALUE(isolate, accessor->Fill(array, value, start, end),
                            Nothing<bool>());

  // It's possible the JSArray's 'length' property was assigned to after the
  // length was loaded due to user code during argument coercion of the start
  // and end parameters. The spec algorithm does a Set, meaning the length would
  // grow as needed during the fill.
  //
  // ElementAccessor::Fill is able to grow the backing store as needed, but we
  // need to ensure the JSArray's length is correctly set in case the user
  // assigned a smaller value.
  if (Object::NumberValue(array->length()) < end) {
    CHECK(accessor->SetLength(array, end).FromJust());
  }

  return Just(true);
}
}  // namespace

BUILTIN(ArrayPrototypeFill) {
  HandleScope scope(isolate);

  // 1. Let O be ? ToObject(this value).
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, receiver, Object::ToObject(isolate, args.receiver()));

  // 2. Let len be ? ToLength(? Get(O, "length")).
  double length;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, length, GetLengthProperty(isolate, receiver));

  // 3. Let relativeStart be ? ToInteger(start).
  // 4. If relativeStart < 0, let k be max((len + relativeStart), 0);
  //    else let k be min(relativeStart, len).
  Handle<Object> start = args.atOrUndefined(isolate, 2);

  double start_index;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, start_index, GetRelativeIndex(isolate, length, start, 0));

  // 5. If end is undefined, let relativeEnd be len;
  //    else let relativeEnd be ? ToInteger(end).
  // 6. If relativeEnd < 0, let final be max((len + relativeEnd), 0);
  //    else let final be min(relativeEnd, len).
  Handle<Object> end = args.atOrUndefined(isolate, 3);

  double end_index;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, end_index, GetRelativeIndex(isolate, length, end, length));

  if (start_index >= end_index) return *receiver;

  // Ensure indexes are within array bounds
  DCHECK_LE(0, start_index);
  DCHECK_LE(start_index, end_index);
  DCHECK_LE(end_index, length);

  Handle<Object> value = args.atOrUndefined(isolate, 1);

  bool success;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, success,
      TryFastArrayFill(isolate, &args, receiver, value, start_index,
                       end_index));
  if (success) return *receiver;
  return GenericArrayFill(isolate, receiver, value, start_index, end_index);
}

namespace {
V8_WARN_UNUSED_RESULT Tagged<Object> GenericArrayPush(Isolate* isolate,
                                                      BuiltinArguments* args) {
  // 1. Let O be ? ToObject(this value).
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, receiver, Object::ToObject(isolate, args->receiver()));

  // 2. Let len be ? ToLength(? Get(O, "length")).
  Handle<Object> raw_length_number;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, raw_length_number,
      Object::GetLengthFromArrayLike(isolate, receiver));

  // 3. Let args be a List whose elements are, in left to right order,
  //    the arguments that were passed to this function invocation.
  // 4. Let arg_count be the number of elements in args.
  int arg_count = args->length() - 1;

  // 5. If len + arg_count > 2^53-1, throw a TypeError exception.
  double length = Object::NumberValue(*raw_length_number);
  if (arg_count > kMaxSafeInteger - length) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kPushPastSafeLength,
                              isolate->factory()->NewNumberFromInt(arg_count),
                              raw_length_number));
  }

  // 6. Repeat, while args is not empty.
  for (int i = 0; i < arg_count; ++i) {
    // a. Remove the first element from args and let E be the value of the
    //    element.
    Handle<Object> element = args->at(i + 1);

    // b. Perform ? Set(O, ! ToString(len), E, true).
    if (length <= JSObject::kMaxElementIndex) {
      RETURN_FAILURE_ON_EXCEPTION(
          isolate, Object::SetElement(isolate, receiver, length, element,
                                      ShouldThrow::kThrowOnError));
    } else {
      PropertyKey key(isolate, length);
      LookupIterator it(isolate, receiver, key);
      MAYBE_RETURN(Object::SetProperty(&it, element, StoreOrigin::kMaybeKeyed,
                                       Just(ShouldThrow::kThrowOnError)),
                   ReadOnlyRoots(isolate).exception());
    }

    // c. Let len be len+1.
    ++length;
  }

  // 7. Perform ? Set(O, "length", len, true).
  Handle<Object> final_length = isolate->factory()->NewNumber(length);
  RETURN_FAILURE_ON_EXCEPTION(
      isolate, Object::SetProperty(isolate, receiver,
                                   isolate->factory()->length_string(),
                                   final_length, StoreOrigin::kMaybeKeyed,
                                   Just(ShouldThrow::kThrowOnError)));

  // 8. Return len.
  return *final_length;
}
}  // namespace

BUILTIN(ArrayPush) {
  HandleScope scope(isolate);
  Handle<Object> receiver = args.receiver();
  if (!EnsureJSArrayWithWritableFastElements(isolate, receiver, &args, 1,
                                             args.length() - 1)) {
    return GenericArrayPush(isolate, &args);
  }

  Handle<JSArray> array = Cast<JSArray>(receiver);
  bool has_read_only_length = JSArray::HasReadOnlyLength(array);

  if (has_read_only_length) {
    return GenericArrayPush(isolate, &args);
  }

  // Fast Elements Path
  int to_add = args.length() - 1;
  uint32_t len = static_cast<uint32_t>(Object::NumberValue(array->length()));
  if (to_add == 0) return *isolate->factory()->NewNumberFromUint(len);

  // Currently fixed arrays cannot grow too big, so we should never hit this.
  DCHECK_LE(to_add, Smi::kMaxValue - Smi::ToInt(array->length()));

  ElementsAccessor* accessor = array->GetElementsAccessor();
  uint32_t new_length;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, new_length, accessor->Push(array, &args, to_add));
  return *isolate->factory()->NewNumberFromUint((new_length));
}

namespace {

V8_WARN_UNUSED_RESULT Tagged<Object> GenericArrayPop(Isolate* isolate,
                                                     BuiltinArguments* args) {
  // 1. Let O be ? ToObject(this value).
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, receiver, Object::ToObject(isolate, args->receiver()));

  // 2. Let len be ? ToLength(? Get(O, "length")).
  Handle<Object> raw_length_number;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, raw_length_number,
      Object::GetLengthFromArrayLike(isolate, receiver));
  double length = Object::NumberValue(*raw_length_number);

  // 3. If len is zero, then.
  if (length == 0) {
    // a. Perform ? Set(O, "length", 0, true).
    RETURN_FAILURE_ON_EXCEPTION(
        isolate, Object::SetProperty(isolate, receiver,
                                     isolate->factory()->length_string(),
                                     Handle<Smi>(Smi::zero(), isolate),
                                     StoreOrigin::kMaybeKeyed,
                                     Just(ShouldThrow::kThrowOnError)));

    // b. Return undefined.
    return ReadOnlyRoots(isolate).undefined_value();
  }

  // 4. Else len > 0.
  // a. Let new_len be len-1.
  Handle<Object> new_length = isolate->factory()->NewNumber(length - 1);

  // b. Let index be ! ToString(newLen).
  Handle<String> index = isolate->factory()->NumberToString(new_length);

  // c. Let element be ? Get(O, index).
  Handle<Object> element;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, element, Object::GetPropertyOrElement(isolate, receiver, index));

  // d. Perform ? DeletePropertyOrThrow(O, index).
  MAYBE_RETURN(JSReceiver::DeletePropertyOrElement(isolate, receiver, index,
                                                   LanguageMode::kStrict),
               ReadOnlyRoots(isolate).exception());

  // e. Perform ? Set(O, "length", newLen, true).
  RETURN_FAILURE_ON_EXCEPTION(
      isolate, Object::SetProperty(isolate, receiver,
                                   isolate->factory()->length_string(),
                                   new_length, StoreOrigin::kMaybeKeyed,
                                   Just(ShouldThrow::kThrowOnError)));

  // f. Return element.
  return *element;
}

}  // namespace

BUILTIN(ArrayPop) {
  HandleScope scope(isolate);
  Handle<Object> receiver = args.receiver();
  if (!EnsureJSArrayWithWritableFastElements(isolate, receiver, nullptr, 0,
                                             0)) {
    return GenericArrayPop(isolate, &args);
  }
  Handle<JSArray> array = Cast<JSArray>(receiver);

  uint32_t len = static_cast<uint32_t>(Object::NumberValue(array->length()));

  if (JSArray::HasReadOnlyLength(array)) {
    return GenericArrayPop(isolate, &args);
  }
  if (len == 0) return ReadOnlyRoots(isolate).undefined_value();

  Handle<Object> result;
  if (IsJSArrayFastElementMovingAllowed(isolate, Cast<JSArray>(*receiver))) {
    // Fast Elements Path
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, result, array->GetElementsAccessor()->Pop(array));
  } else {
    // Use Slow Lookup otherwise
    uint32_t new_length = len - 1;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, result, JSReceiver::GetElement(isolate, array, new_length));

    // The length could have become read-only during the last GetElement() call,
    // so check again.
    if (JSArray::HasReadOnlyLength(array)) {
      THROW_NEW_ERROR_RETURN_FAILURE(
          isolate, NewTypeError(MessageTemplate::kStrictReadOnlyProperty,
                                isolate->factory()->length_string(),
                                Object::TypeOf(isolate, array), array));
    }
    bool set_len_ok;
    MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, set_len_ok, JSArray::SetLength(array, new_length));
  }

  return *result;
}

namespace {

// Returns true, iff we can use ElementsAccessor for shifting.
V8_WARN_UNUSED_RESULT bool CanUseFastArrayShift(Isolate* isolate,
                                                Handle<JSReceiver> receiver) {
  if (V8_COMPRESS_POINTERS_8GB_BOOL) return false;

  if (!EnsureJSArrayWithWritableFastElements(isolate, receiver, nullptr, 0,
                                             0) ||
      !IsJSArrayFastElementMovingAllowed(isolate, Cast<JSArray>(*receiver))) {
    return false;
  }

  Handle<JSArray> array = Cast<JSArray>(receiver);
  return !JSArray::HasReadOnlyLength(array);
}

V8_WARN_UNUSED_RESULT Tagged<Object> GenericArrayShift(
    Isolate* isolate, Handle<JSReceiver> receiver, double length) {
  // 4. Let first be ? Get(O, "0").
  Handle<Object> first;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, first,
                                     Object::GetElement(isolate, receiver, 0));

  // 5. Let k be 1.
  double k = 1;

  // 6. Repeat, while k < len.
  while (k < length) {
    // a. Let from be ! ToString(k).
    Handle<String> from =
        isolate->factory()->NumberToString(isolate->factory()->NewNumber(k));

    // b. Let to be ! ToString(k-1).
    Handle<String> to = isolate->factory()->NumberToString(
        isolate->factory()->NewNumber(k - 1));

    // c. Let fromPresent be ? HasProperty(O, from).
    bool from_present;
    MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, from_present,
        JSReceiver::HasProperty(isolate, receiver, from));

    // d. If fromPresent is true, then.
    if (from_present) {
      // i. Let fromVal be ? Get(O, from).
      Handle<Object> from_val;
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
          isolate, from_val,
          Object::GetPropertyOrElement(isolate, receiver, from));

      // ii. Perform ? Set(O, to, fromVal, true).
      RETURN_FAILURE_ON_EXCEPTION(
          isolate,
          Object::SetPropertyOrElement(isolate, receiver, to, from_val,
                                       Just(ShouldThrow::kThrowOnError)));
    } else {  // e. Else fromPresent is false,
      // i. Perform ? DeletePropertyOrThrow(O, to).
      MAYBE_RETURN(JSReceiver::DeletePropertyOrElement(isolate, receiver, to,
                                                       LanguageMode::kStrict),
                   ReadOnlyRoots(isolate).exception());
    }

    // f. Increase k by 1.
    ++k;
  }

  // 7. Perform ? DeletePropertyOrThrow(O, ! ToString(len-1)).
  Handle<String> new_length = isolate->factory()->NumberToString(
      isolate->factory()->NewNumber(length - 1));
  MAYBE_RETURN(JSReceiver::DeletePropertyOrElement(
                   isolate, receiver, new_length, LanguageMode::kStrict),
               ReadOnlyRoots(isolate).exception());

  // 8. Perform ? Set(O, "length", len-1, true).
  RETURN_FAILURE_ON_EXCEPTION(isolate,
                              SetLengthProperty(isolate, receiver, length - 1));

  // 9. Return first.
  return *first;
}
}  // namespace

BUILTIN(ArrayShift) {
  HandleScope scope(isolate);

  // 1. Let O be ? ToObject(this value).
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, receiver, Object::ToObject(isolate, args.receiver()));

  // 2. Let len be ? ToLength(? Get(O, "length")).
  double length;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, length, GetLengthProperty(isolate, receiver));

  // 3. If len is zero, then.
  if (length == 0) {
    // a. Perform ? Set(O, "length", 0, true).
    RETURN_FAILURE_ON_EXCEPTION(isolate,
                                SetLengthProperty(isolate, receiver, length));

    // b. Return undefined.
    return ReadOnlyRoots(isolate).undefined_value();
  }

  if (CanUseFastArrayShift(isolate, receiver)) {
    Handle<JSArray> array = Cast<JSArray>(receiver);
    RETURN_RESULT_OR_FAILURE(isolate,
                             array->GetElementsAccessor()->Shift(array));
  }

  return GenericArrayShift(isolate, receiver, length);
}

BUILTIN(ArrayUnshift) {
  HandleScope scope(isolate);
  DCHECK(IsJSArray(*args.receiver()));
  Handle<JSArray> array = Cast<JSArray>(args.receiver());

  // These are checked in the Torque builtin.
  DCHECK(array->map()->is_extensible());
  DCHECK(!IsDictionaryElementsKind(array->GetElementsKind()));
  DCHECK(IsJSArrayFastElementMovingAllowed(isolate, *array));
  DCHECK(!isolate->IsInitialArrayPrototype(*array));

  MatchArrayElementsKindToArguments(isolate, array, &args, 1,
                                    args.length() - 1);

  int to_add = args.length() - 1;
  if (to_add == 0) return array->length();

  // Currently fixed arrays cannot grow too big, so we should never hit this.
  DCHECK_LE(to_add, Smi::kMaxValue - Smi::ToInt(array->length()));
  DCHECK(!JSArray::HasReadOnlyLength(array));

  ElementsAccessor* accessor = array->GetElementsAccessor();
  uint32_t new_length;
  MAYBE_ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, new_length, accessor->Unshift(array, &args, to_add));
  return Smi::FromInt(new_length);
}

// Array Concat -------------------------------------------------------------

namespace {

/**
 * A simple visitor visits every element of Array's.
 * The backend storage can be a fixed array for fast elements case,
 * or a dictionary for sparse array. Since Dictionary is a subtype
 * of FixedArray, the class can be used by both fast and slow cases.
 * The second parameter of the constructor, fast_elements, specifies
 * whether the storage is a FixedArray or Dictionary.
 *
 * An index limit is used to deal with the situation that a result array
 * length overflows 32-bit non-negative integer.
 */
class ArrayConcatVisitor {
 public:
  ArrayConcatVisitor(
      Isolate* isolate,
      DirectHandle<UnionOf<JSReceiver, FixedArray, NumberDictionary>> storage,
      bool fast_elements)
      : isolate_(isolate),
        storage_(isolate->global_handles()->Create(*storage)),
        index_offset_(0u),
        bit_field_(FastElementsField::encode(fast_elements) |
                   ExceedsLimitField::encode(false) |
                   IsFixedArrayField::encode(IsFixedArray(*storage, isolate)) |
                   HasSimpleElementsField::encode(
                       IsFixedArray(*storage, isolate) ||
                       // Don't take fast path for storages that might have
                       // side effects when storing to them.
                       (!IsCustomElementsReceiverMap(storage->map(isolate)) &&
                        !IsJSTypedArray(*storage, isolate)))) {
    DCHECK_IMPLIES(this->fast_elements(), is_fixed_array());
  }

  ~ArrayConcatVisitor() { clear_storage(); }

  V8_WARN_UNUSED_RESULT bool visit(uint32_t i, Handle<Object> elm) {
    uint32_t index = index_offset_ + i;

    // Note we use >=kMaxArrayLength instead of the more appropriate
    // >kMaxArrayIndex here due to overflowing arithmetic and
    // increase_index_offset.
    if (i >= JSArray::kMaxArrayLength - index_offset_) {
      set_exceeds_array_limit(true);
      // Exception hasn't been thrown at this point. Return true to
      // break out, and caller will throw. !visit would imply that
      // there is already an exception.
      return true;
    }

    if (!is_fixed_array()) {
      MAYBE_RETURN(JSReceiver::CreateDataProperty(
                       isolate_, Cast<JSReceiver>(storage_),
                       PropertyKey(isolate_, index), elm, Just(kThrowOnError)),
                   false);
      return true;
    }

    if (fast_elements()) {
      if (index < static_cast<uint32_t>(storage_fixed_array()->length())) {
        storage_fixed_array()->set(index, *elm);
        return true;
      }
      // Our initial estimate of length was foiled, possibly by
      // getters on the arrays increasing the length of later arrays
      // during iteration.
      // This shouldn't happen in anything but pathological cases.
      SetDictionaryMode();
      // Fall-through to dictionary mode.
    }
    DCHECK(!fast_elements());
    Handle<NumberDictionary> dict(Cast<NumberDictionary>(*storage_), isolate_);
    // The object holding this backing store has just been allocated, so
    // it cannot yet be used as a prototype.
    Handle<JSObject> not_a_prototype_holder;
    Handle<NumberDictionary> result = NumberDictionary::Set(
        isolate_, dict, index, elm, not_a_prototype_holder);
    if (!result.is_identical_to(dict)) {
      // Dictionary needed to grow.
      clear_storage();
      set_storage(*result);
    }
    return true;
  }

  uint32_t index_offset() const { return index_offset_; }

  void increase_index_offset(uint32_t delta) {
    if (JSArray::kMaxArrayLength - index_offset_ < delta) {
      index_offset_ = JSArray::kMaxArrayLength;
    } else {
      index_offset_ += delta;
    }
    // If the initial length estimate was off (see special case in visit()),
    // but the array blowing the limit didn't contain elements beyond the
    // provided-for index range, go to dictionary mode now.
    if (fast_elements() &&
        index_offset_ >
            static_cast<uint32_t>(Cast<FixedArrayBase>(*storage_)->length())) {
      SetDictionaryMode();
    }
  }

  bool exceeds_array_limit() const {
    return ExceedsLimitField::decode(bit_field_);
  }

  Handle<JSArray> ToArray() {
    DCHECK(is_fixed_array());
    Handle<JSArray> array = isolate_->factory()->NewJSArray(0);
    DirectHandle<Number> length =
        isolate_->factory()->NewNumber(static_cast<double>(index_offset_));
    DirectHandle<Map> map = JSObject::GetElementsTransitionMap(
        array, fast_elements() ? HOLEY_ELEMENTS : DICTIONARY_ELEMENTS);
    {
      DisallowGarbageCollection no_gc;
      Tagged<JSArray> raw = *array;
      raw->set_length(*length);
      raw->set_elements(*storage_fixed_array());
      raw->set_map(isolate_, *map, kReleaseStore);
    }
    return array;
  }

  V8_WARN_UNUSED_RESULT MaybeHandle<JSReceiver> ToJSReceiver() {
    DCHECK(!is_fixed_array());
    Handle<JSReceiver> result = Cast<JSReceiver>(storage_);
    Handle<Object> length =
        isolate_->factory()->NewNumber(static_cast<double>(index_offset_));
    RETURN_ON_EXCEPTION(
        isolate_, Object::SetProperty(isolate_, result,
                                      isolate_->factory()->length_string(),
                                      length, StoreOrigin::kMaybeKeyed,
                                      Just(ShouldThrow::kThrowOnError)));
    return result;
  }
  bool has_simple_elements() const {
    return HasSimpleElementsField::decode(bit_field_);
  }

 private:
  // Convert storage to dictionary mode.
  void SetDictionaryMode() {
    DCHECK(fast_elements() && is_fixed_array());
    DirectHandle<FixedArray> current_storage = storage_fixed_array();
    Handle<NumberDictionary> slow_storage(
        NumberDictionary::New(isolate_, current_storage->length()));
    uint32_t current_length = static_cast<uint32_t>(current_storage->length());
    FOR_WITH_HANDLE_SCOPE(
        isolate_, uint32_t, i = 0, i, i < current_length, i++, {
          Handle<Object> element(current_storage->get(i), isolate_);
          if (!IsTheHole(*element, isolate_)) {
            // The object holding this backing store has just been allocated, so
            // it cannot yet be used as a prototype.
            Handle<JSObject> not_a_prototype_holder;
            Handle<NumberDictionary> new_storage = NumberDictionary::Set(
                isolate_, slow_storage, i, element, not_a_prototype_holder);
            if (!new_storage.is_identical_to(slow_storage)) {
              slow_storage = loop_scope.CloseAndEscape(new_storage);
            }
          }
        });
    clear_storage();
    set_storage(*slow_storage);
    set_fast_elements(false);
  }

  inline void clear_storage() { GlobalHandles::Destroy(storage_.location()); }

  inline void set_storage(Tagged<FixedArray> storage) {
    DCHECK(is_fixed_array());
    DCHECK(has_simple_elements());
    storage_ = isolate_->global_handles()->Create(storage);
  }

  using FastElementsField = base::BitField<bool, 0, 1>;
  using ExceedsLimitField = base::BitField<bool, 1, 1>;
  using IsFixedArrayField = base::BitField<bool, 2, 1>;
  using HasSimpleElementsField = base::BitField<bool, 3, 1>;

  bool fast_elements() const { return FastElementsField::decode(bit_field_); }
  void set_fast_elements(bool fast) {
    bit_field_ = FastElementsField::update(bit_field_, fast);
  }
  void set_exceeds_array_limit(bool exceeds) {
    bit_field_ = ExceedsLimitField::update(bit_field_, exceeds);
  }
  bool is_fixed_array() const { return IsFixedArrayField::decode(bit_field_); }
  Handle<FixedArray> storage_fixed_array() {
    DCHECK(is_fixed_array());
    DCHECK(has_simple_elements());
    return Cast<FixedArray>(storage_);
  }

  Isolate* isolate_;
  Handle<UnionOf<JSReceiver, FixedArray, NumberDictionary>>
      storage_;  // Always a global handle.
  // Index after last seen index. Always less than or equal to
  // JSArray::kMaxArrayLength.
  uint32_t index_offset_;
  uint32_t bit_field_;
};

uint32_t EstimateElementCount(Isolate* isolate, DirectHandle<JSArray> array) {
  DisallowGarbageCollection no_gc;
  uint32_t length = s
```