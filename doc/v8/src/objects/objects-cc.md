Response:
The user wants a summary of the functionalities present in the provided C++ source code `v8/src/objects/objects.cc`. The request includes several constraints:

1. **List functionalities:** Identify and list the primary purposes of the code.
2. **Torque check:** Determine if the file would be a Torque file if its extension was `.tq`.
3. **JavaScript relation:** If the code interacts with JavaScript features, provide illustrative JavaScript examples.
4. **Code logic inference:**  If there's demonstrable code logic, provide example inputs and outputs.
5. **Common programming errors:** Identify potential programming mistakes related to this code.
6. **Concise summary:** Provide a high-level overview of the file's role, given it's the first of eight parts.

**Mental Model:**

The code is a C++ file in the V8 JavaScript engine, specifically within the `objects` directory. This suggests it's likely involved in defining and manipulating JavaScript object representations within the engine. The numerous includes point to interactions with various aspects of V8, including:

* **API:**  Interaction with the V8 embedding API.
* **AST:** Abstract Syntax Tree manipulation (likely for type information).
* **Compilation:**  Integration with the compilation pipeline.
* **Execution:** Runtime execution of JavaScript code.
* **Heap:** Memory management for JavaScript objects.
* **IC:** Inline caching for optimization.
* **Objects:** Definition and manipulation of different JavaScript object types.
* **Strings:** String handling.
* **Numbers:** Number representation and manipulation.
* **Booleans:** Boolean value handling.
* **Type conversion:** Conversion between JavaScript types.
* **Comparison:**  Implementation of JavaScript comparison operators.

**Plan:**

1. **Functionality Listing:**  Scan the code for key functions and concepts. Focus on type conversions (`ToNumber`, `ToString`, `ToBoolean`, `ToObject`), comparisons (`Compare`, `Equals`), object wrapping (`WrapForRead`), and utility functions for determining object properties and types.
2. **Torque Check:**  Based on my knowledge of Torque, `.cc` files are generally C++ implementations, while `.tq` files are for Torque definitions. This file would *not* be a Torque file if it ended in `.tq`.
3. **JavaScript Relation:** For the identified functionalities, provide simple JavaScript examples that demonstrate these operations (e.g., `Number()`, `String()`, `Boolean()`, `==`, `<`, type coercion).
4. **Code Logic Inference:**  Focus on the comparison functions (`Compare`, `Equals`). Provide examples of how different JavaScript types are compared and the expected output.
5. **Common Programming Errors:** Think about common mistakes related to type coercion and comparison in JavaScript, and how the C++ code might relate to preventing or handling these errors.
6. **Summary:** Synthesize the identified functionalities into a concise summary, emphasizing that this part likely focuses on the fundamental definition and manipulation of JavaScript objects and their types within the V8 engine.

**Pre-computation/Analysis:**

* **Type Conversions:**  The code explicitly implements the abstract operations for converting values to primitives (`ToPrimitive`), numbers (`ToNumber`, `ToInt32`, `ToUint32`), strings (`ToString`), and booleans (`ToBoolean`).
* **Comparisons:** The `Compare` and `Equals` functions detail the logic for JavaScript's abstract relational and equality comparisons, including handling different types (numbers, strings, booleans, BigInts).
* **Object Representation:** The inclusion of numerous object headers (`js-array-inl.h`, `map-inl.h`, etc.) strongly suggests this file deals with the internal representation of JavaScript objects.

**Constraint Checklist & Confidence Score:**

1. List functionalities: Yes
2. Torque check: Yes
3. JavaScript relation: Yes
4. Code logic inference: Yes
5. Common programming errors: Yes
6. Concise summary: Yes

Confidence Score: 5/5

Strategizing complete. I will now proceed with generating the response following the outlined plan.
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/objects.h"

#include <algorithm>
#include <cmath>
#include <memory>
#include <optional>
#include <sstream>
#include <vector>

#include "src/api/api-arguments-inl.h"
#include "src/api/api-natives.h"
#include "src/api/api.h"
#include "src/ast/ast.h"
#include "src/ast/scopes.h"
#include "src/base/bits.h"
#include "src/base/debug/stack_trace.h"
#include "src/base/logging.h"
#include "src/base/overflowing-math.h"
#include "src/base/utils/random-number-generator.h"
#include "src/builtins/accessors.h"
#include "src/builtins/builtins.h"
#include "src/codegen/compiler.h"
#include "src/codegen/source-position-table.h"
#include "src/common/globals.h"
#include "src/common/message-template.h"
#include "src/date/date.h"
#include "src/debug/debug.h"
#include "src/diagnostics/code-tracer.h"
#include "src/execution/arguments.h"
#include "src/execution/execution.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/isolate-utils-inl.h"
#include "src/execution/isolate-utils.h"
#include "src/execution/microtask-queue.h"
#include "src/execution/protectors-inl.h"
#include "src/heap/factory-inl.h"
#include "src/heap/heap-inl.h"
#include "src/heap/local-factory-inl.h"
#include "src/heap/read-only-heap.h"
#include "src/ic/ic.h"
#include "src/init/bootstrapper.h"
#include "src/logging/counters.h"
#include "src/logging/log.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/allocation-site-inl.h"
#include "src/objects/allocation-site-scopes.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/bigint.h"
#include "src/objects/call-site-info-inl.h"
#include "src/objects/cell-inl.h"
#include "src/objects/code-inl.h"
#include "src/objects/compilation-cache-table-inl.h"
#include "src/objects/debug-objects-inl.h"
#include "src/objects/dictionary.h"
#include "src/objects/elements.h"
#include "src/objects/embedder-data-array-inl.h"
#include "src/objects/field-index-inl.h"
#include "src/objects/field-index.h"
#include "src/objects/field-type.h"
#include "src/objects/foreign.h"
#include "src/objects/free-space-inl.h"
#include "src/objects/function-kind.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/heap-object-inl.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/js-disposable-stack-inl.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/js-regexp-string-iterator.h"
#include "src/objects/js-weak-refs-inl.h"
#include "src/objects/keys.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/lookup-inl.h"
#include "src/objects/map-inl.h"
#include "src/objects/map-updater.h"
#include "src/objects/map.h"
#include "src/objects/megadom-handler-inl.h"
#include "src/objects/microtask-inl.h"
#include "src/objects/module-inl.h"
#include "src/objects/objects-body-descriptors-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/promise-inl.h"
#include "src/objects/promise.h"
#include "src/objects/property-descriptor-object-inl.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/property-details.h"
#include "src/objects/prototype.h"
#include "src/objects/slots-atomic-inl.h"
#include "src/objects/string-comparator.h"
#include "src/objects/string-set-inl.h"
#include "src/objects/struct-inl.h"
#include "src/objects/template-objects-inl.h"
#include "src/objects/transitions-inl.h"
#include "src/parsing/preparse-data.h"
#include "src/regexp/regexp.h"
#include "src/roots/roots.h"
#include "src/snapshot/deserializer.h"
#include "src/strings/string-builder-inl.h"
#include "src/strings/string-search.h"
#include "src/strings/string-stream.h"
#include "src/strings/unicode-decoder.h"
#include "src/strings/unicode-inl.h"
#include "src/utils/hex-format.h"
#include "src/utils/identity-map.h"
#include "src/utils/ostreams.h"
#include "src/utils/sha-256.h"
#include "src/utils/utils-inl.h"
#include "src/zone/zone.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

#ifdef V8_INTL_SUPPORT
#include "src/objects/js-break-iterator.h"
#include "src/objects/js-collator.h"
#include "src/objects/js-date-time-format.h"
#include "src/objects/js-list-format.h"
#include "src/objects/js-locale.h"
#include "src/objects/js-number-format.h"
#include "src/objects/js-plural-rules.h"
#include "src/objects/js-relative-time-format.h"
#include "src/objects/js-segment-iterator.h"
#include "src/objects/js-segmenter.h"
#include "src/objects/js-segments.h"
#endif  // V8_INTL_SUPPORT

namespace v8::internal {

ShouldThrow GetShouldThrow(Isolate* isolate, Maybe<ShouldThrow> should_throw) {
  if (should_throw.IsJust()) return should_throw.FromJust();

  LanguageMode mode = isolate->context()->scope_info()->language_mode();
  if (mode == LanguageMode::kStrict) return kThrowOnError;

  for (StackFrameIterator it(isolate, isolate->thread_local_top(),
                             StackFrameIterator::NoHandles{});
       !it.done(); it.Advance()) {
    if (!it.frame()->is_javascript()) continue;

    // Get the language mode from closure.
    JavaScriptFrame* js_frame = static_cast<JavaScriptFrame*>(it.frame());
    std::vector<Tagged<SharedFunctionInfo>> functions;
    js_frame->GetFunctions(&functions);
    LanguageMode closure_language_mode = functions.back()->language_mode();
    if (closure_language_mode > mode) {
      mode = closure_language_mode;
    }
    break;
  }

  return is_sloppy(mode) ? kDontThrow : kThrowOnError;
}

bool ComparisonResultToBool(Operation op, ComparisonResult result) {
  switch (op) {
    case Operation::kLessThan:
      return result == ComparisonResult::kLessThan;
    case Operation::kLessThanOrEqual:
      return result == ComparisonResult::kLessThan ||
             result == ComparisonResult::kEqual;
    case Operation::kGreaterThan:
      return result == ComparisonResult::kGreaterThan;
    case Operation::kGreaterThanOrEqual:
      return result == ComparisonResult::kGreaterThan ||
             result == ComparisonResult::kEqual;
    default:
      break;
  }
  UNREACHABLE();
}

std::string ToString(InstanceType instance_type) {
  if (InstanceTypeChecker::IsJSApiObject(instance_type)) {
    std::stringstream ss;
    ss << "[api object] "
       << static_cast<int16_t>(instance_type) -
              i::Internals::kFirstJSApiObjectType;
    return ss.str();
  }
  switch (instance_type) {
#define WRITE_TYPE(TYPE) \
  case TYPE:             \
    return #TYPE;
    INSTANCE_TYPE_LIST(WRITE_TYPE)
#undef WRITE_TYPE
  }

  std::stringstream ss;
  ss << "[unknown instance type " << static_cast<int16_t>(instance_type) << "]";
  return ss.str();
}

std::ostream& operator<<(std::ostream& os, InstanceType instance_type) {
  return os << ToString(instance_type);
}

std::ostream& operator<<(std::ostream& os, PropertyCellType type) {
  switch (type) {
    case PropertyCellType::kUndefined:
      return os << "Undefined";
    case PropertyCellType::kConstant:
      return os << "Constant";
    case PropertyCellType::kConstantType:
      return os << "ConstantType";
    case PropertyCellType::kMutable:
      return os << "Mutable";
    case PropertyCellType::kInTransition:
      return os << "InTransition";
  }
  UNREACHABLE();
}

// static
Handle<FieldType> Object::OptimalType(Tagged<Object> obj, Isolate* isolate,
                                      Representation representation) {
  if (representation.IsNone()) return FieldType::None(isolate);
  if (v8_flags.track_field_types) {
    if (representation.IsHeapObject() && IsHeapObject(obj)) {
      // We can track only JavaScript objects with stable maps.
      DirectHandle<Map> map(Cast<HeapObject>(obj)->map(), isolate);
      if (map->is_stable() && IsJSReceiverMap(*map)) {
        return FieldType::Class(map, isolate);
      }
    }
  }
  return FieldType::Any(isolate);
}

Handle<UnionOf<JSAny, Hole>> Object::NewStorageFor(
    Isolate* isolate, Handle<UnionOf<JSAny, Hole>> object,
    Representation representation) {
  if (!representation.IsDouble()) return object;
  Handle<HeapNumber> result = isolate->factory()->NewHeapNumberWithHoleNaN();
  if (IsUninitialized(*object, isolate)) {
    result->set_value_as_bits(kHoleNanInt64);
  } else if (IsHeapNumber(*object)) {
    // Ensure that all bits of the double value are preserved.
    result->set_value_as_bits(Cast<HeapNumber>(*object)->value_as_bits());
  } else {
    result->set_value(Cast<Smi>(*object).value());
  }
  return result;
}

template <AllocationType allocation_type, typename IsolateT>
Handle<JSAny> Object::WrapForRead(IsolateT* isolate, Handle<JSAny> object,
                                  Representation representation) {
  DCHECK(!IsUninitialized(*object, isolate));
  if (!representation.IsDouble()) {
    DCHECK(Object::FitsRepresentation(*object, representation));
    return object;
  }
  return isolate->factory()->template NewHeapNumberFromBits<allocation_type>(
      Cast<HeapNumber>(*object)->value_as_bits());
}

template Handle<JSAny> Object::WrapForRead<AllocationType::kYoung>(
    Isolate* isolate, Handle<JSAny> object, Representation representation);
template Handle<JSAny> Object::WrapForRead<AllocationType::kOld>(
    LocalIsolate* isolate, Handle<JSAny> object, Representation representation);

MaybeHandle<JSReceiver> Object::ToObjectImpl(Isolate* isolate,
                                             DirectHandle<Object> object,
                                             const char* method_name) {
  DCHECK(!IsJSReceiver(*object));  // Use ToObject() for fast path.
  DirectHandle<Context> native_context = isolate->native_context();
  Handle<JSFunction> constructor;
  if (IsSmi(*object)) {
    constructor = handle(native_context->number_function(), isolate);
  } else {
    int constructor_function_index =
        Cast<HeapObject>(object)->map()->GetConstructorFunctionIndex();
    if (constructor_function_index == Map::kNoConstructorFunctionIndex) {
      if (method_name != nullptr) {
        THROW_NEW_ERROR(
            isolate, NewTypeError(MessageTemplate::kCalledOnNullOrUndefined,
                                  isolate->factory()->NewStringFromAsciiChecked(
                                      method_name)));
      }
      THROW_NEW_ERROR(isolate,
                      NewTypeError(MessageTemplate::kUndefinedOrNullToObject));
    }
    constructor = handle(
        Cast<JSFunction>(native_context->get(constructor_function_index)),
        isolate);
  }
  Handle<JSObject> result = isolate->factory()->NewJSObject(constructor);
  Cast<JSPrimitiveWrapper>(result)->set_value(Cast<JSAny>(*object));
  return result;
}

// ES6 section 9.2.1.2, OrdinaryCallBindThis for sloppy callee.
// static
MaybeHandle<JSReceiver> Object::ConvertReceiver(Isolate* isolate,
                                                Handle<Object> object) {
  if (IsJSReceiver(*object)) return Cast<JSReceiver>(object);
  if (IsNullOrUndefined(*object, isolate)) {
    return isolate->global_proxy();
  }
  return Object::ToObject(isolate, object);
}

// static
MaybeHandle<Number> Object::ConvertToNumber(Isolate* isolate,
                                            Handle<Object> input) {
  while (true) {
    if (IsNumber(*input)) {
      return Cast<Number>(input);
    }
    if (IsString(*input)) {
      return String::ToNumber(isolate, Cast<String>(input));
    }
    if (IsOddball(*input)) {
      return Oddball::ToNumber(isolate, Cast<Oddball>(input));
    }
    if (IsSymbol(*input)) {
      THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kSymbolToNumber));
    }
    if (IsBigInt(*input)) {
      THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kBigIntToNumber));
    }
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, input,
        JSReceiver::ToPrimitive(isolate, Cast<JSReceiver>(input),
                                ToPrimitiveHint::kNumber));
  }
}

// static
MaybeHandle<Numeric> Object::ConvertToNumeric(Isolate* isolate,
                                              Handle<Object> input) {
  while (true) {
    if (IsNumber(*input)) {
      return Cast<Number>(input);
    }
    if (IsString(*input)) {
      return String::ToNumber(isolate, Cast<String>(input));
    }
    if (IsOddball(*input)) {
      return Oddball::ToNumber(isolate, Cast<Oddball>(input));
    }
    if (IsSymbol(*input)) {
      THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kSymbolToNumber));
    }
    if (IsBigInt(*input)) {
      return Cast<BigInt>(input);
    }
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, input,
        JSReceiver::ToPrimitive(isolate, Cast<JSReceiver>(input),
                                ToPrimitiveHint::kNumber));
  }
}

// static
MaybeHandle<Number> Object::ConvertToInteger(Isolate* isolate,
                                             Handle<Object> input) {
  ASSIGN_RETURN_ON_EXCEPTION(isolate, input, ConvertToNumber(isolate, input));
  if (IsSmi(*input)) return Cast<Smi>(input);
  return isolate->factory()->NewNumber(
      DoubleToInteger(Cast<HeapNumber>(*input)->value()));
}

// static
MaybeHandle<Number> Object::ConvertToInt32(Isolate* isolate,
                                           Handle<Object> input) {
  ASSIGN_RETURN_ON_EXCEPTION(isolate, input, ConvertToNumber(isolate, input));
  if (IsSmi(*input)) return Cast<Smi>(input);
  return isolate->factory()->NewNumberFromInt(
      DoubleToInt32(Cast<HeapNumber>(*input)->value()));
}

// static
MaybeHandle<Number> Object::ConvertToUint32(Isolate* isolate,
                                            Handle<Object> input) {
  ASSIGN_RETURN_ON_EXCEPTION(isolate, input, ConvertToNumber(isolate, input));
  if (IsSmi(*input))
    return handle(Smi::ToUint32Smi(Cast<Smi>(*input)), isolate);
  return isolate->factory()->NewNumberFromUint(
      DoubleToUint32(Cast<HeapNumber>(*input)->value()));
}

// static
MaybeHandle<Name> Object::ConvertToName(Isolate* isolate,
                                        Handle<Object> input) {
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, input,
      Object::ToPrimitive(isolate, input, ToPrimitiveHint::kString));
  if (IsName(*input)) return Cast<Name>(input);
  return ToString(isolate, input);
}

// ES6 7.1.14
// static
MaybeHandle<Object> Object::ConvertToPropertyKey(Isolate* isolate,
                                                 Handle<Object> value) {
  // 1. Let key be ToPrimitive(argument, hint String).
  MaybeHandle<Object> maybe_key =
      Object::ToPrimitive(isolate, value, ToPrimitiveHint::kString);
  // 2. ReturnIfAbrupt(key).
  Handle<Object> key;
  if (!maybe_key.ToHandle(&key)) return key;
  // 3. If Type(key) is Symbol, then return key.
  if (IsSymbol(*key)) return key;
  // 4. Return ToString(key).
  // Extending spec'ed behavior, we'd be happy to return an element index.
  if (IsSmi(*key)) return key;
  if (IsHeapNumber(*key)) {
    uint32_t uint_value;
    if (Object::ToArrayLength(*value, &uint_value) &&
        uint_value <= static_cast<uint32_t>(Smi::kMaxValue)) {
      return handle(Smi::FromInt(static_cast<int>(uint_value)), isolate);
    }
  }
  return Object::ToString(isolate, key);
}

// static
MaybeHandle<String> Object::ConvertToString(Isolate* isolate,
                                            Handle<Object> input) {
  while (true) {
    if (IsOddball(*input)) {
      return handle(Cast<Oddball>(input)->to_string(), isolate);
    }
    if (IsNumber(*input)) {
      return isolate->factory()->NumberToString(input);
    }
    if (IsSymbol(*input)) {
      THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kSymbolToString));
    }
    if (IsBigInt(*input)) {
      return BigInt::ToString(isolate, Cast<BigInt>(input));
    }
#if V8_ENABLE_WEBASSEMBLY
    // We generally don't let the WasmNull escape into the JavaScript world,
    // but some builtins may encounter it when called directly from Wasm code.
    if (IsWasmNull(*input)) {
      return isolate->factory()->null_string();
    }
#endif
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, input,
        JSReceiver::ToPrimitive(isolate, Cast<JSReceiver>(input),
                                ToPrimitiveHint::kString));
    // The previous isString() check happened in Object::ToString and thus we
    // put it at the end of the loop in this helper.
    if (IsString(*input)) {
      return Cast<String>(input);
    }
  }
}

namespace {

bool IsErrorObject(Isolate* isolate, Handle<Object> object) {
  if (!IsJSObject(*object)) return false;
  return ErrorUtils::HasErrorStackSymbolOwnProperty(isolate,
                                                    Cast<JSObject>(object));
}

Handle<String> AsStringOrEmpty(Isolate* isolate, Handle<Object> object) {
  return IsString(*object) ? Cast<String>(object)
                           : isolate->factory()->empty_string();
}

DirectHandle<String> NoSideEffectsErrorToString(Isolate* isolate,
                                                Handle<JSReceiver> error) {
  Handle<Name> name_key = isolate->factory()->name_string();
  Handle<Object> name = JSReceiver::GetDataProperty(isolate, error, name_key);
  Handle<String> name_str = AsStringOrEmpty(isolate, name);

  Handle<Name> msg_key = isolate->factory()->message_string();
  Handle<Object> msg = JSReceiver::GetDataProperty(isolate, error, msg_key);
  DirectHandle<String> msg_str = AsStringOrEmpty(isolate, msg);

  if (name_str->length() == 0) return msg_str;
  if (msg_str->length() == 0) return name_str;

  constexpr const char error_suffix[] = "<a very large string>";
  constexpr uint32_t error_suffix_size = sizeof(error_suffix);
  uint32_t suffix_size = std::min(error_suffix_size, msg_str->length());

  IncrementalStringBuilder builder(isolate);
  if (name_str->length() + suffix_size + 2 /* ": " */ > String::kMaxLength) {
    constexpr const char connector[] = "... : ";
    int connector_size = sizeof(connector);
    DirectHandle<String> truncated_name =
        isolate->factory()->NewProperSubString(
            name_str, 0,
            name_str->length() - error_suffix_size - connector_size);
    builder.AppendString(truncated_name);
    builder.AppendCStringLiteral(connector);
    builder.AppendCStringLiteral(error_suffix);
  } else {
    builder.AppendString(name_str);
    builder.AppendCStringLiteral(": ");
    if (builder.Length() + msg_str->length() <= String::kMaxLength) {
      builder.AppendString(msg_str);
    } else {
      builder.AppendCStringLiteral(error_suffix);
    }
  }

  return builder.Finish().ToHandleChecked();
}

}  // namespace

// static
MaybeDirectHandle<String> Object::NoSideEffectsToMaybeString(
    Isolate* isolate, DirectHandle<Object> input) {
  DisallowJavascriptExecution no_js(isolate);

  if (IsString(*input) || IsNumber(*input) || IsOddball(*input)) {
    return Object::ToString(isolate, input).ToHandleChecked();
  } else if (IsJSProxy(*input)) {
    DirectHandle<Object> currInput = input;
    do {
      Tagged<HeapObject> target = Cast<JSProxy>(currInput)->target(isolate);
      currInput = direct_handle(target, isolate);
    } while (IsJSProxy(*currInput));
    return NoSideEffectsToString(isolate, currInput);
  } else if (IsBigInt(*input)) {
    return BigInt::NoSideEffectsToString(isolate, Cast<BigInt>(input));
  } else if (IsJSFunctionOrBoundFunctionOrWrappedFunction(*input)) {
    // -- F u n c t i o n
    Handle<String> fun_str;
    if (IsJSBoundFunction(*input)) {
      fun_str = JSBoundFunction::ToString(Cast<JSBoundFunction>(input));
    } else if (IsJSWrappedFunction(*input)) {
      fun_str = JSWrappedFunction::ToString(Cast<JSWrappedFunction>(input));
    } else {
      DCHECK(IsJSFunction(*input));
      fun_str = JSFunction::ToString(Cast<JSFunction>(input));
    }

    if (fun_str->length() > 128) {
      IncrementalStringBuilder builder(isolate);
      builder.AppendString(isolate->factory()->NewSubString(fun_str, 0, 111));
      builder.AppendCStringLiteral("...<omitted>...");
      builder.AppendString(isolate->factory()->NewSubString(
          fun_str, fun_str->length() - 2, fun_str->length()));

      return builder.Finish().ToHandleChecked();
    }
    return fun_str;
  } else if (IsSymbol(*input)) {
    // -- S y m b o l
    DirectHandle<Symbol> symbol = Cast<Symbol>(input);

    if (symbol->is_private_name()) {
      return DirectHandle<String>(Cast<String>(symbol->description()), isolate);
    }

    IncrementalStringBuilder builder(isolate);
    builder.AppendCStringLiteral("Symbol(");
    if (IsString(symbol->description())) {
      Handle<String> description =
          handle(Cast<String>(symbol->description()), isolate);
      if (description->length() > 128) {
        builder.AppendString(
            isolate->factory()->NewSubString(description, 0, 56));
        builder.AppendCStringLiteral("...<omitted>...");
        builder.AppendString(isolate->factory()->NewSubString(
            description, description->length() - 56, description->length()));
      } else {
        builder.AppendString(description);
      }
    }
    builder.AppendCharacter(')');

    return builder.Finish().ToHandleChecked();
  } else if (IsJSReceiver(*input)) {
    // -- J S R e c e i v e r
    Handle<Object> indirect_input = indirect_handle(input, isolate);
    Handle<JSReceiver> receiver = Cast<JSReceiver>(indirect_input);
    DirectHandle<Object> to_string = JSReceiver::GetDataProperty(
        isolate, receiver, isolate->factory()->toString_string());

    if (IsErrorObject(isolate, indirect_input) ||
        *to_string == *isolate->error_to_string()) {
      // When internally formatting error objects, use a side-effects-free
      // version of Error.prototype.toString independent of the actually
      // installed toString method.
      return NoSideEffectsErrorToString(isolate, receiver);
    } else if (*to_string == *isolate->object_to_string()) {
      Handle<Object> ctor = JSReceiver::GetDataProperty(
          isolate, receiver, isolate->factory()->constructor_string());
      if (IsJSFunctionOrBoundFunctionOrWrappedFunction(*ctor)) {
        DirectHandle<String> ctor_name;
        if (IsJSBoundFunction(*ctor)) {
          ctor_name =
              JSBoundFunction::GetName(isolate, Cast<JSBoundFunction>(ctor))
                  .ToHandleChecked();
        } else if (IsJSFunction(*ctor)) {
          ctor_name = JSFunction::GetName(isolate, Cast<JSFunction>(ctor));
        }

        if (ctor_name->length() != 0) {
          IncrementalStringBuilder builder(isolate);
          builder.AppendCStringLiteral("#<");
          builder.AppendString(ctor_name);
          builder.AppendCharacter('>');

          return builder.Finish().ToHandleChecked();
        }
      }
    }
  }
  return {};
}

// static
DirectHandle<String> Object::NoSideEffectsToString(Isolate* isolate,
                                                   DirectHandle<Object> input) {
  DisallowJavascriptExecution no_js(isolate);

  // Try to convert input to a meaningful string.
  MaybeDirectHandle<String> maybe_string =
      NoSideEffectsToMaybeString(isolate, input);
  DirectHandle<String> string_handle;
  if (maybe_string.ToHandle(&string_handle)) {
    return string_handle;
  }

  // At this point, input is either none of the above or a JSReceiver.

  Handle<JSReceiver> receiver;
  if (IsJSReceiver(*input)) {
    receiver = indirect_handle(Cast<JSReceiver>(input), isolate);
  } else {
    // This is the only case where Object::ToObject throws.
    DCHECK(!IsSmi(*input));
    int constructor_function_index =
        Cast<HeapObject>(input)->map()->GetConstructorFunctionIndex();
    if (constructor_function_index == Map::kNoConstructorFunctionIndex) {
      return isolate->factory()->NewStringFromAsciiChecked("[object Unknown]");
    }

    receiver = Object::ToObjectImpl(isolate, input).ToHandleChecked();
  }

  DirectHandle<String> builtin_tag =
      direct_handle(receiver->class_name(), isolate);
  DirectHandle<Object> tag_obj = JSReceiver::GetDataProperty(
      isolate, receiver, isolate->factory()->to_string_tag_symbol());
  DirectHandle<String> tag =
      IsString(*tag_obj) ? Cast<String>(tag_obj) : builtin_tag;

  IncrementalStringBuilder builder(isolate);
  builder.AppendCStringLiteral("[object ");
  builder.AppendString(tag);
  builder.AppendCharacter(']');

  return builder.Finish().ToHandleChecked();
}

// static
MaybeHandle<Number> Object::ConvertToLength(Isolate* isolate,
                                            Handle<Object> input) {
  ASSIGN_RETURN_ON_EXCEPTION(isolate, input, ToNumber(isolate, input
### 提示词
```
这是目录为v8/src/objects/objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/objects.h"

#include <algorithm>
#include <cmath>
#include <memory>
#include <optional>
#include <sstream>
#include <vector>

#include "src/api/api-arguments-inl.h"
#include "src/api/api-natives.h"
#include "src/api/api.h"
#include "src/ast/ast.h"
#include "src/ast/scopes.h"
#include "src/base/bits.h"
#include "src/base/debug/stack_trace.h"
#include "src/base/logging.h"
#include "src/base/overflowing-math.h"
#include "src/base/utils/random-number-generator.h"
#include "src/builtins/accessors.h"
#include "src/builtins/builtins.h"
#include "src/codegen/compiler.h"
#include "src/codegen/source-position-table.h"
#include "src/common/globals.h"
#include "src/common/message-template.h"
#include "src/date/date.h"
#include "src/debug/debug.h"
#include "src/diagnostics/code-tracer.h"
#include "src/execution/arguments.h"
#include "src/execution/execution.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/isolate-utils-inl.h"
#include "src/execution/isolate-utils.h"
#include "src/execution/microtask-queue.h"
#include "src/execution/protectors-inl.h"
#include "src/heap/factory-inl.h"
#include "src/heap/heap-inl.h"
#include "src/heap/local-factory-inl.h"
#include "src/heap/read-only-heap.h"
#include "src/ic/ic.h"
#include "src/init/bootstrapper.h"
#include "src/logging/counters.h"
#include "src/logging/log.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/allocation-site-inl.h"
#include "src/objects/allocation-site-scopes.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/bigint.h"
#include "src/objects/call-site-info-inl.h"
#include "src/objects/cell-inl.h"
#include "src/objects/code-inl.h"
#include "src/objects/compilation-cache-table-inl.h"
#include "src/objects/debug-objects-inl.h"
#include "src/objects/dictionary.h"
#include "src/objects/elements.h"
#include "src/objects/embedder-data-array-inl.h"
#include "src/objects/field-index-inl.h"
#include "src/objects/field-index.h"
#include "src/objects/field-type.h"
#include "src/objects/foreign.h"
#include "src/objects/free-space-inl.h"
#include "src/objects/function-kind.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/heap-object-inl.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/js-disposable-stack-inl.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/js-regexp-string-iterator.h"
#include "src/objects/js-weak-refs-inl.h"
#include "src/objects/keys.h"
#include "src/objects/literal-objects-inl.h"
#include "src/objects/lookup-inl.h"
#include "src/objects/map-inl.h"
#include "src/objects/map-updater.h"
#include "src/objects/map.h"
#include "src/objects/megadom-handler-inl.h"
#include "src/objects/microtask-inl.h"
#include "src/objects/module-inl.h"
#include "src/objects/objects-body-descriptors-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/promise-inl.h"
#include "src/objects/promise.h"
#include "src/objects/property-descriptor-object-inl.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/property-details.h"
#include "src/objects/prototype.h"
#include "src/objects/slots-atomic-inl.h"
#include "src/objects/string-comparator.h"
#include "src/objects/string-set-inl.h"
#include "src/objects/struct-inl.h"
#include "src/objects/template-objects-inl.h"
#include "src/objects/transitions-inl.h"
#include "src/parsing/preparse-data.h"
#include "src/regexp/regexp.h"
#include "src/roots/roots.h"
#include "src/snapshot/deserializer.h"
#include "src/strings/string-builder-inl.h"
#include "src/strings/string-search.h"
#include "src/strings/string-stream.h"
#include "src/strings/unicode-decoder.h"
#include "src/strings/unicode-inl.h"
#include "src/utils/hex-format.h"
#include "src/utils/identity-map.h"
#include "src/utils/ostreams.h"
#include "src/utils/sha-256.h"
#include "src/utils/utils-inl.h"
#include "src/zone/zone.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

#ifdef V8_INTL_SUPPORT
#include "src/objects/js-break-iterator.h"
#include "src/objects/js-collator.h"
#include "src/objects/js-date-time-format.h"
#include "src/objects/js-list-format.h"
#include "src/objects/js-locale.h"
#include "src/objects/js-number-format.h"
#include "src/objects/js-plural-rules.h"
#include "src/objects/js-relative-time-format.h"
#include "src/objects/js-segment-iterator.h"
#include "src/objects/js-segmenter.h"
#include "src/objects/js-segments.h"
#endif  // V8_INTL_SUPPORT

namespace v8::internal {

ShouldThrow GetShouldThrow(Isolate* isolate, Maybe<ShouldThrow> should_throw) {
  if (should_throw.IsJust()) return should_throw.FromJust();

  LanguageMode mode = isolate->context()->scope_info()->language_mode();
  if (mode == LanguageMode::kStrict) return kThrowOnError;

  for (StackFrameIterator it(isolate, isolate->thread_local_top(),
                             StackFrameIterator::NoHandles{});
       !it.done(); it.Advance()) {
    if (!it.frame()->is_javascript()) continue;

    // Get the language mode from closure.
    JavaScriptFrame* js_frame = static_cast<JavaScriptFrame*>(it.frame());
    std::vector<Tagged<SharedFunctionInfo>> functions;
    js_frame->GetFunctions(&functions);
    LanguageMode closure_language_mode = functions.back()->language_mode();
    if (closure_language_mode > mode) {
      mode = closure_language_mode;
    }
    break;
  }

  return is_sloppy(mode) ? kDontThrow : kThrowOnError;
}

bool ComparisonResultToBool(Operation op, ComparisonResult result) {
  switch (op) {
    case Operation::kLessThan:
      return result == ComparisonResult::kLessThan;
    case Operation::kLessThanOrEqual:
      return result == ComparisonResult::kLessThan ||
             result == ComparisonResult::kEqual;
    case Operation::kGreaterThan:
      return result == ComparisonResult::kGreaterThan;
    case Operation::kGreaterThanOrEqual:
      return result == ComparisonResult::kGreaterThan ||
             result == ComparisonResult::kEqual;
    default:
      break;
  }
  UNREACHABLE();
}

std::string ToString(InstanceType instance_type) {
  if (InstanceTypeChecker::IsJSApiObject(instance_type)) {
    std::stringstream ss;
    ss << "[api object] "
       << static_cast<int16_t>(instance_type) -
              i::Internals::kFirstJSApiObjectType;
    return ss.str();
  }
  switch (instance_type) {
#define WRITE_TYPE(TYPE) \
  case TYPE:             \
    return #TYPE;
    INSTANCE_TYPE_LIST(WRITE_TYPE)
#undef WRITE_TYPE
  }

  std::stringstream ss;
  ss << "[unknown instance type " << static_cast<int16_t>(instance_type) << "]";
  return ss.str();
}

std::ostream& operator<<(std::ostream& os, InstanceType instance_type) {
  return os << ToString(instance_type);
}

std::ostream& operator<<(std::ostream& os, PropertyCellType type) {
  switch (type) {
    case PropertyCellType::kUndefined:
      return os << "Undefined";
    case PropertyCellType::kConstant:
      return os << "Constant";
    case PropertyCellType::kConstantType:
      return os << "ConstantType";
    case PropertyCellType::kMutable:
      return os << "Mutable";
    case PropertyCellType::kInTransition:
      return os << "InTransition";
  }
  UNREACHABLE();
}

// static
Handle<FieldType> Object::OptimalType(Tagged<Object> obj, Isolate* isolate,
                                      Representation representation) {
  if (representation.IsNone()) return FieldType::None(isolate);
  if (v8_flags.track_field_types) {
    if (representation.IsHeapObject() && IsHeapObject(obj)) {
      // We can track only JavaScript objects with stable maps.
      DirectHandle<Map> map(Cast<HeapObject>(obj)->map(), isolate);
      if (map->is_stable() && IsJSReceiverMap(*map)) {
        return FieldType::Class(map, isolate);
      }
    }
  }
  return FieldType::Any(isolate);
}

Handle<UnionOf<JSAny, Hole>> Object::NewStorageFor(
    Isolate* isolate, Handle<UnionOf<JSAny, Hole>> object,
    Representation representation) {
  if (!representation.IsDouble()) return object;
  Handle<HeapNumber> result = isolate->factory()->NewHeapNumberWithHoleNaN();
  if (IsUninitialized(*object, isolate)) {
    result->set_value_as_bits(kHoleNanInt64);
  } else if (IsHeapNumber(*object)) {
    // Ensure that all bits of the double value are preserved.
    result->set_value_as_bits(Cast<HeapNumber>(*object)->value_as_bits());
  } else {
    result->set_value(Cast<Smi>(*object).value());
  }
  return result;
}

template <AllocationType allocation_type, typename IsolateT>
Handle<JSAny> Object::WrapForRead(IsolateT* isolate, Handle<JSAny> object,
                                  Representation representation) {
  DCHECK(!IsUninitialized(*object, isolate));
  if (!representation.IsDouble()) {
    DCHECK(Object::FitsRepresentation(*object, representation));
    return object;
  }
  return isolate->factory()->template NewHeapNumberFromBits<allocation_type>(
      Cast<HeapNumber>(*object)->value_as_bits());
}

template Handle<JSAny> Object::WrapForRead<AllocationType::kYoung>(
    Isolate* isolate, Handle<JSAny> object, Representation representation);
template Handle<JSAny> Object::WrapForRead<AllocationType::kOld>(
    LocalIsolate* isolate, Handle<JSAny> object, Representation representation);

MaybeHandle<JSReceiver> Object::ToObjectImpl(Isolate* isolate,
                                             DirectHandle<Object> object,
                                             const char* method_name) {
  DCHECK(!IsJSReceiver(*object));  // Use ToObject() for fast path.
  DirectHandle<Context> native_context = isolate->native_context();
  Handle<JSFunction> constructor;
  if (IsSmi(*object)) {
    constructor = handle(native_context->number_function(), isolate);
  } else {
    int constructor_function_index =
        Cast<HeapObject>(object)->map()->GetConstructorFunctionIndex();
    if (constructor_function_index == Map::kNoConstructorFunctionIndex) {
      if (method_name != nullptr) {
        THROW_NEW_ERROR(
            isolate, NewTypeError(MessageTemplate::kCalledOnNullOrUndefined,
                                  isolate->factory()->NewStringFromAsciiChecked(
                                      method_name)));
      }
      THROW_NEW_ERROR(isolate,
                      NewTypeError(MessageTemplate::kUndefinedOrNullToObject));
    }
    constructor = handle(
        Cast<JSFunction>(native_context->get(constructor_function_index)),
        isolate);
  }
  Handle<JSObject> result = isolate->factory()->NewJSObject(constructor);
  Cast<JSPrimitiveWrapper>(result)->set_value(Cast<JSAny>(*object));
  return result;
}

// ES6 section 9.2.1.2, OrdinaryCallBindThis for sloppy callee.
// static
MaybeHandle<JSReceiver> Object::ConvertReceiver(Isolate* isolate,
                                                Handle<Object> object) {
  if (IsJSReceiver(*object)) return Cast<JSReceiver>(object);
  if (IsNullOrUndefined(*object, isolate)) {
    return isolate->global_proxy();
  }
  return Object::ToObject(isolate, object);
}

// static
MaybeHandle<Number> Object::ConvertToNumber(Isolate* isolate,
                                            Handle<Object> input) {
  while (true) {
    if (IsNumber(*input)) {
      return Cast<Number>(input);
    }
    if (IsString(*input)) {
      return String::ToNumber(isolate, Cast<String>(input));
    }
    if (IsOddball(*input)) {
      return Oddball::ToNumber(isolate, Cast<Oddball>(input));
    }
    if (IsSymbol(*input)) {
      THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kSymbolToNumber));
    }
    if (IsBigInt(*input)) {
      THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kBigIntToNumber));
    }
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, input,
        JSReceiver::ToPrimitive(isolate, Cast<JSReceiver>(input),
                                ToPrimitiveHint::kNumber));
  }
}

// static
MaybeHandle<Numeric> Object::ConvertToNumeric(Isolate* isolate,
                                              Handle<Object> input) {
  while (true) {
    if (IsNumber(*input)) {
      return Cast<Number>(input);
    }
    if (IsString(*input)) {
      return String::ToNumber(isolate, Cast<String>(input));
    }
    if (IsOddball(*input)) {
      return Oddball::ToNumber(isolate, Cast<Oddball>(input));
    }
    if (IsSymbol(*input)) {
      THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kSymbolToNumber));
    }
    if (IsBigInt(*input)) {
      return Cast<BigInt>(input);
    }
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, input,
        JSReceiver::ToPrimitive(isolate, Cast<JSReceiver>(input),
                                ToPrimitiveHint::kNumber));
  }
}

// static
MaybeHandle<Number> Object::ConvertToInteger(Isolate* isolate,
                                             Handle<Object> input) {
  ASSIGN_RETURN_ON_EXCEPTION(isolate, input, ConvertToNumber(isolate, input));
  if (IsSmi(*input)) return Cast<Smi>(input);
  return isolate->factory()->NewNumber(
      DoubleToInteger(Cast<HeapNumber>(*input)->value()));
}

// static
MaybeHandle<Number> Object::ConvertToInt32(Isolate* isolate,
                                           Handle<Object> input) {
  ASSIGN_RETURN_ON_EXCEPTION(isolate, input, ConvertToNumber(isolate, input));
  if (IsSmi(*input)) return Cast<Smi>(input);
  return isolate->factory()->NewNumberFromInt(
      DoubleToInt32(Cast<HeapNumber>(*input)->value()));
}

// static
MaybeHandle<Number> Object::ConvertToUint32(Isolate* isolate,
                                            Handle<Object> input) {
  ASSIGN_RETURN_ON_EXCEPTION(isolate, input, ConvertToNumber(isolate, input));
  if (IsSmi(*input))
    return handle(Smi::ToUint32Smi(Cast<Smi>(*input)), isolate);
  return isolate->factory()->NewNumberFromUint(
      DoubleToUint32(Cast<HeapNumber>(*input)->value()));
}

// static
MaybeHandle<Name> Object::ConvertToName(Isolate* isolate,
                                        Handle<Object> input) {
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, input,
      Object::ToPrimitive(isolate, input, ToPrimitiveHint::kString));
  if (IsName(*input)) return Cast<Name>(input);
  return ToString(isolate, input);
}

// ES6 7.1.14
// static
MaybeHandle<Object> Object::ConvertToPropertyKey(Isolate* isolate,
                                                 Handle<Object> value) {
  // 1. Let key be ToPrimitive(argument, hint String).
  MaybeHandle<Object> maybe_key =
      Object::ToPrimitive(isolate, value, ToPrimitiveHint::kString);
  // 2. ReturnIfAbrupt(key).
  Handle<Object> key;
  if (!maybe_key.ToHandle(&key)) return key;
  // 3. If Type(key) is Symbol, then return key.
  if (IsSymbol(*key)) return key;
  // 4. Return ToString(key).
  // Extending spec'ed behavior, we'd be happy to return an element index.
  if (IsSmi(*key)) return key;
  if (IsHeapNumber(*key)) {
    uint32_t uint_value;
    if (Object::ToArrayLength(*value, &uint_value) &&
        uint_value <= static_cast<uint32_t>(Smi::kMaxValue)) {
      return handle(Smi::FromInt(static_cast<int>(uint_value)), isolate);
    }
  }
  return Object::ToString(isolate, key);
}

// static
MaybeHandle<String> Object::ConvertToString(Isolate* isolate,
                                            Handle<Object> input) {
  while (true) {
    if (IsOddball(*input)) {
      return handle(Cast<Oddball>(input)->to_string(), isolate);
    }
    if (IsNumber(*input)) {
      return isolate->factory()->NumberToString(input);
    }
    if (IsSymbol(*input)) {
      THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kSymbolToString));
    }
    if (IsBigInt(*input)) {
      return BigInt::ToString(isolate, Cast<BigInt>(input));
    }
#if V8_ENABLE_WEBASSEMBLY
    // We generally don't let the WasmNull escape into the JavaScript world,
    // but some builtins may encounter it when called directly from Wasm code.
    if (IsWasmNull(*input)) {
      return isolate->factory()->null_string();
    }
#endif
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, input,
        JSReceiver::ToPrimitive(isolate, Cast<JSReceiver>(input),
                                ToPrimitiveHint::kString));
    // The previous isString() check happened in Object::ToString and thus we
    // put it at the end of the loop in this helper.
    if (IsString(*input)) {
      return Cast<String>(input);
    }
  }
}

namespace {

bool IsErrorObject(Isolate* isolate, Handle<Object> object) {
  if (!IsJSObject(*object)) return false;
  return ErrorUtils::HasErrorStackSymbolOwnProperty(isolate,
                                                    Cast<JSObject>(object));
}

Handle<String> AsStringOrEmpty(Isolate* isolate, Handle<Object> object) {
  return IsString(*object) ? Cast<String>(object)
                           : isolate->factory()->empty_string();
}

DirectHandle<String> NoSideEffectsErrorToString(Isolate* isolate,
                                                Handle<JSReceiver> error) {
  Handle<Name> name_key = isolate->factory()->name_string();
  Handle<Object> name = JSReceiver::GetDataProperty(isolate, error, name_key);
  Handle<String> name_str = AsStringOrEmpty(isolate, name);

  Handle<Name> msg_key = isolate->factory()->message_string();
  Handle<Object> msg = JSReceiver::GetDataProperty(isolate, error, msg_key);
  DirectHandle<String> msg_str = AsStringOrEmpty(isolate, msg);

  if (name_str->length() == 0) return msg_str;
  if (msg_str->length() == 0) return name_str;

  constexpr const char error_suffix[] = "<a very large string>";
  constexpr uint32_t error_suffix_size = sizeof(error_suffix);
  uint32_t suffix_size = std::min(error_suffix_size, msg_str->length());

  IncrementalStringBuilder builder(isolate);
  if (name_str->length() + suffix_size + 2 /* ": " */ > String::kMaxLength) {
    constexpr const char connector[] = "... : ";
    int connector_size = sizeof(connector);
    DirectHandle<String> truncated_name =
        isolate->factory()->NewProperSubString(
            name_str, 0,
            name_str->length() - error_suffix_size - connector_size);
    builder.AppendString(truncated_name);
    builder.AppendCStringLiteral(connector);
    builder.AppendCStringLiteral(error_suffix);
  } else {
    builder.AppendString(name_str);
    builder.AppendCStringLiteral(": ");
    if (builder.Length() + msg_str->length() <= String::kMaxLength) {
      builder.AppendString(msg_str);
    } else {
      builder.AppendCStringLiteral(error_suffix);
    }
  }

  return builder.Finish().ToHandleChecked();
}

}  // namespace

// static
MaybeDirectHandle<String> Object::NoSideEffectsToMaybeString(
    Isolate* isolate, DirectHandle<Object> input) {
  DisallowJavascriptExecution no_js(isolate);

  if (IsString(*input) || IsNumber(*input) || IsOddball(*input)) {
    return Object::ToString(isolate, input).ToHandleChecked();
  } else if (IsJSProxy(*input)) {
    DirectHandle<Object> currInput = input;
    do {
      Tagged<HeapObject> target = Cast<JSProxy>(currInput)->target(isolate);
      currInput = direct_handle(target, isolate);
    } while (IsJSProxy(*currInput));
    return NoSideEffectsToString(isolate, currInput);
  } else if (IsBigInt(*input)) {
    return BigInt::NoSideEffectsToString(isolate, Cast<BigInt>(input));
  } else if (IsJSFunctionOrBoundFunctionOrWrappedFunction(*input)) {
    // -- F u n c t i o n
    Handle<String> fun_str;
    if (IsJSBoundFunction(*input)) {
      fun_str = JSBoundFunction::ToString(Cast<JSBoundFunction>(input));
    } else if (IsJSWrappedFunction(*input)) {
      fun_str = JSWrappedFunction::ToString(Cast<JSWrappedFunction>(input));
    } else {
      DCHECK(IsJSFunction(*input));
      fun_str = JSFunction::ToString(Cast<JSFunction>(input));
    }

    if (fun_str->length() > 128) {
      IncrementalStringBuilder builder(isolate);
      builder.AppendString(isolate->factory()->NewSubString(fun_str, 0, 111));
      builder.AppendCStringLiteral("...<omitted>...");
      builder.AppendString(isolate->factory()->NewSubString(
          fun_str, fun_str->length() - 2, fun_str->length()));

      return builder.Finish().ToHandleChecked();
    }
    return fun_str;
  } else if (IsSymbol(*input)) {
    // -- S y m b o l
    DirectHandle<Symbol> symbol = Cast<Symbol>(input);

    if (symbol->is_private_name()) {
      return DirectHandle<String>(Cast<String>(symbol->description()), isolate);
    }

    IncrementalStringBuilder builder(isolate);
    builder.AppendCStringLiteral("Symbol(");
    if (IsString(symbol->description())) {
      Handle<String> description =
          handle(Cast<String>(symbol->description()), isolate);
      if (description->length() > 128) {
        builder.AppendString(
            isolate->factory()->NewSubString(description, 0, 56));
        builder.AppendCStringLiteral("...<omitted>...");
        builder.AppendString(isolate->factory()->NewSubString(
            description, description->length() - 56, description->length()));
      } else {
        builder.AppendString(description);
      }
    }
    builder.AppendCharacter(')');

    return builder.Finish().ToHandleChecked();
  } else if (IsJSReceiver(*input)) {
    // -- J S R e c e i v e r
    Handle<Object> indirect_input = indirect_handle(input, isolate);
    Handle<JSReceiver> receiver = Cast<JSReceiver>(indirect_input);
    DirectHandle<Object> to_string = JSReceiver::GetDataProperty(
        isolate, receiver, isolate->factory()->toString_string());

    if (IsErrorObject(isolate, indirect_input) ||
        *to_string == *isolate->error_to_string()) {
      // When internally formatting error objects, use a side-effects-free
      // version of Error.prototype.toString independent of the actually
      // installed toString method.
      return NoSideEffectsErrorToString(isolate, receiver);
    } else if (*to_string == *isolate->object_to_string()) {
      Handle<Object> ctor = JSReceiver::GetDataProperty(
          isolate, receiver, isolate->factory()->constructor_string());
      if (IsJSFunctionOrBoundFunctionOrWrappedFunction(*ctor)) {
        DirectHandle<String> ctor_name;
        if (IsJSBoundFunction(*ctor)) {
          ctor_name =
              JSBoundFunction::GetName(isolate, Cast<JSBoundFunction>(ctor))
                  .ToHandleChecked();
        } else if (IsJSFunction(*ctor)) {
          ctor_name = JSFunction::GetName(isolate, Cast<JSFunction>(ctor));
        }

        if (ctor_name->length() != 0) {
          IncrementalStringBuilder builder(isolate);
          builder.AppendCStringLiteral("#<");
          builder.AppendString(ctor_name);
          builder.AppendCharacter('>');

          return builder.Finish().ToHandleChecked();
        }
      }
    }
  }
  return {};
}

// static
DirectHandle<String> Object::NoSideEffectsToString(Isolate* isolate,
                                                   DirectHandle<Object> input) {
  DisallowJavascriptExecution no_js(isolate);

  // Try to convert input to a meaningful string.
  MaybeDirectHandle<String> maybe_string =
      NoSideEffectsToMaybeString(isolate, input);
  DirectHandle<String> string_handle;
  if (maybe_string.ToHandle(&string_handle)) {
    return string_handle;
  }

  // At this point, input is either none of the above or a JSReceiver.

  Handle<JSReceiver> receiver;
  if (IsJSReceiver(*input)) {
    receiver = indirect_handle(Cast<JSReceiver>(input), isolate);
  } else {
    // This is the only case where Object::ToObject throws.
    DCHECK(!IsSmi(*input));
    int constructor_function_index =
        Cast<HeapObject>(input)->map()->GetConstructorFunctionIndex();
    if (constructor_function_index == Map::kNoConstructorFunctionIndex) {
      return isolate->factory()->NewStringFromAsciiChecked("[object Unknown]");
    }

    receiver = Object::ToObjectImpl(isolate, input).ToHandleChecked();
  }

  DirectHandle<String> builtin_tag =
      direct_handle(receiver->class_name(), isolate);
  DirectHandle<Object> tag_obj = JSReceiver::GetDataProperty(
      isolate, receiver, isolate->factory()->to_string_tag_symbol());
  DirectHandle<String> tag =
      IsString(*tag_obj) ? Cast<String>(tag_obj) : builtin_tag;

  IncrementalStringBuilder builder(isolate);
  builder.AppendCStringLiteral("[object ");
  builder.AppendString(tag);
  builder.AppendCharacter(']');

  return builder.Finish().ToHandleChecked();
}

// static
MaybeHandle<Number> Object::ConvertToLength(Isolate* isolate,
                                            Handle<Object> input) {
  ASSIGN_RETURN_ON_EXCEPTION(isolate, input, ToNumber(isolate, input));
  if (IsSmi(*input)) {
    int value = std::max(Smi::ToInt(*input), 0);
    return handle(Smi::FromInt(value), isolate);
  }
  double len = DoubleToInteger(Cast<HeapNumber>(*input)->value());
  if (len <= 0.0) {
    return handle(Smi::zero(), isolate);
  } else if (len >= kMaxSafeInteger) {
    len = kMaxSafeInteger;
  }
  return isolate->factory()->NewNumber(len);
}

// static
MaybeHandle<Number> Object::ConvertToIndex(Isolate* isolate,
                                           Handle<Object> input,
                                           MessageTemplate error_index) {
  if (IsUndefined(*input, isolate)) return handle(Smi::zero(), isolate);
  ASSIGN_RETURN_ON_EXCEPTION(isolate, input, ToNumber(isolate, input));
  if (IsSmi(*input) && Smi::ToInt(*input) >= 0) return Cast<Smi>(input);
  double len = DoubleToInteger(Object::NumberValue(Cast<Number>(*input)));
  Handle<Number> js_len = isolate->factory()->NewNumber(len);
  if (len < 0.0 || len > kMaxSafeInteger) {
    THROW_NEW_ERROR(isolate, NewRangeError(error_index, js_len));
  }
  return js_len;
}

template <typename IsolateT>
// static
bool Object::BooleanValue(Tagged<Object> obj, IsolateT* isolate) {
  if (IsSmi(obj)) return Smi::ToInt(obj) != 0;
  DCHECK(IsHeapObject(obj));
  if (IsBoolean(obj)) return IsTrue(obj, isolate);
  if (IsNullOrUndefined(obj, isolate)) return false;
#ifdef V8_ENABLE_WEBASSEMBLY
  if (IsWasmNull(obj)) return false;
#endif
  if (IsUndetectable(obj)) return false;  // Undetectable object is false.
  if (IsString(obj)) return Cast<String>(obj)->length() != 0;
  if (IsHeapNumber(obj)) return DoubleToBoolean(Cast<HeapNumber>(obj)->value());
  if (IsBigInt(obj)) return Cast<BigInt>(obj)->ToBoolean();
  return true;
}
template bool Object::BooleanValue(Tagged<Object>, Isolate*);
template bool Object::BooleanValue(Tagged<Object>, LocalIsolate*);

// static
Tagged<Object> Object::ToBoolean(Tagged<Object> obj, Isolate* isolate) {
  if (IsBoolean(obj)) return obj;
  return isolate->heap()->ToBoolean(Object::BooleanValue(obj, isolate));
}

namespace {

// TODO(bmeurer): Maybe we should introduce a marker interface Number,
// where we put all these methods at some point?
ComparisonResult StrictNumberCompare(double x, double y) {
  if (std::isnan(x) || std::isnan(y)) {
    return ComparisonResult::kUndefined;
  } else if (x < y) {
    return ComparisonResult::kLessThan;
  } else if (x > y) {
    return ComparisonResult::kGreaterThan;
  } else {
    return ComparisonResult::kEqual;
  }
}

// See Number case of ES6#sec-strict-equality-comparison
// Returns false if x or y is NaN, treats -0.0 as equal to 0.0.
bool StrictNumberEquals(double x, double y) {
  // Must check explicitly for NaN's on Windows, but -0 works fine.
  if (std::isnan(x) || std::isnan(y)) return false;
  return x == y;
}

bool StrictNumberEquals(const Tagged<Number> x, const Tagged<Number> y) {
  return StrictNumberEquals(Object::NumberValue(x), Object::NumberValue(y));
}

bool StrictNumberEquals(DirectHandle<Number> x, DirectHandle<Number> y) {
  return StrictNumberEquals(*x, *y);
}

ComparisonResult Reverse(ComparisonResult result) {
  if (result == ComparisonResult::kLessThan) {
    return ComparisonResult::kGreaterThan;
  }
  if (result == ComparisonResult::kGreaterThan) {
    return ComparisonResult::kLessThan;
  }
  return result;
}

}  // anonymous namespace

// static
Maybe<ComparisonResult> Object::Compare(Isolate* isolate, Handle<Object> x,
                                        Handle<Object> y) {
  // ES6 section 7.2.11 Abstract Relational Comparison step 3 and 4.
  if (!Object::ToPrimitive(isolate, x, ToPrimitiveHint::kNumber).ToHandle(&x) ||
      !Object::ToPrimitive(isolate, y, ToPrimitiveHint::kNumber).ToHandle(&y)) {
    return Nothing<ComparisonResult>();
  }
  if (IsString(*x) && IsString(*y)) {
    // ES6 section 7.2.11 Abstract Relational Comparison step 5.
    return Just(String::Compare(isolate, Cast<String>(x), Cast<String>(y)));
  }
  if (IsBigInt(*x) && IsString(*y)) {
    return BigInt::CompareToString(isolate, Cast<BigInt>(x), Cast<String>(y));
  }
  if (IsString(*x) && IsBigInt(*y)) {
    Maybe<ComparisonResult> maybe_result =
        BigInt::CompareToString(isolate, Cast<BigInt>(y), Cast<String>(x));
    ComparisonResult result;
    if (maybe_result.To(&result)) {
      return Just(Reverse(result));
    } else {
      return Nothing<ComparisonResult>();
    }
  }
  // ES6 section 7.2.11 Abstract Relational Comparison step 6.
  if (!Object::ToNumeric(isolate, x).ToHandle(&x) ||
      !Object::ToNumeric(isolate, y).ToHandle(&y)) {
    return Nothing<ComparisonResult>();
  }

  bool x_is_number = IsNumber(*x);
  bool y_is_number = IsNumber(*y);
  if (x_is_number && y_is_number) {
    return Just(
        StrictNumberCompare(Object::NumberValue(*x), Object::NumberValue(*y)));
  } else if (!x_is_number && !y_is_number) {
    return Just(BigInt::CompareToBigInt(Cast<BigInt>(x), Cast<BigInt>(y)));
  } else if (x_is_number) {
    return Just(Reverse(BigInt::CompareToNumber(Cast<BigInt>(y), x)));
  } else {
    return Just(BigInt::CompareToNumber(Cast<BigInt>(x), y));
  }
}

Maybe<bool> Object::Equals(Isolate* isolate, Handle<Object> x,
                           Handle<Object> y) {
  // This is the generic version of Abstract Equality Comparison. Must be in
  // sync with CodeStubAssembler::Equal.
  while (true) {
    if (IsNumber(*x)) {
      if (IsNumber(*y)) {
        return Just(StrictNumberEquals(Cast<Number>(*x), Cast<Number>(*y)));
      } else if (IsBoolean(*y)) {
        return Just(StrictNumberEquals(Cast<Number>(*x),
                                       Cast<Oddball>(y)->to_number()));
      } else if (IsString(*y)) {
        return Just(StrictNumberEquals(
            Cast<Number>(x), String::ToNumber(isolate, Cast<String>(y))));
      } else if (IsBigInt(*y)) {
        return Just(BigInt::EqualToNumber(Cast<BigInt>(y), Cast<Number>(x)));
      } else if (IsJSReceiver(*y)) {
        if (!JSReceiver::ToPrimitive(isolate, Cast<JSReceiver>(y))
                 .ToHandle(&y)) {
          return Nothing<bool>();
        }
      } else {
        return Just(false);
      }
    } else if (IsString(*x)) {
      if (IsString(*y)) {
        return Just(String::Equals(isolate, Cast<String>(x), Cast<String>(y)));
      } else if (IsNumber(*y)) {
        x = String::ToNumber(isolate, Cast<String>(x));
        return Just(StrictNumberEquals(Cast<Number>(*x), Cast<Number>(*y)));
      } else if (IsBoolean(*y)) {
        x = String::ToNumber(isolate, Cast<String>(x));
        return Just(StrictNumberEquals(Cast<Number>(*x),
                                       Cast<Oddball>(y)->to_number()));
      } else if (IsBigInt(*y)) {
        return BigInt::EqualToString(isolate, Cast<BigInt>(y), Cast<String>(x));
      } else if (IsJSReceiver(*y)) {
        if (!JSReceiver::ToPrimitive(isolate, Cast<JSReceiver>(y))
                 .ToHandle(&y)) {
          return Nothing<bool>();
        }
      } else {
        return Just(false);
      }
    } else if (IsBoolean(*x)) {
      if (IsOddball(*y)) {
        return Just(x.is_identical_to(y));
      } else if (IsNumber(*y)) {
        return Just(StrictNumberEquals(Cast<Oddball>(x)->to_number(),
                                       Cast<Number>(*y)));
      } else if (IsString(*y)) {
        y = String::ToNumber(isolate, Cast<String>(y));
        return Just(StrictNumberEquals(Cast<Oddball>(x)->to_number(),
                                       Cast<Number>(*y)));
      } else if (IsBigInt(*y)) {
        x = Oddball::ToNumber(isolate, Cast<Oddball>(x));
        return Just(BigInt::EqualToNumber(Cast<BigInt>(y), x));
      } else if (IsJSReceiver(*y)) {
        if (!JSReceiver::ToPrimitive(isolate, Cast<JSReceiver>(y))
                 .ToHandle(&y)) {
          return Nothing<bool>();
        }
        x = Oddball::ToNumber(isolate, Cast<Oddball>(x));
      } else {
        return Just(fa
```