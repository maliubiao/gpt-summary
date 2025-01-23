Response: The user wants a summary of the C++ code provided. The code is part of the V8 Javascript engine, specifically the `objects.cc` file within the `v8/src/objects` directory.

The goal is to understand the functionality of this specific part of the V8 engine. It's also requested to demonstrate the relationship between this C++ code and Javascript functionality with Javascript examples.

Since this is part 1 of 4, the summary should focus on the functionality present in this specific chunk of code.

Looking at the includes, the code seems to be dealing with the fundamental concept of "objects" in V8. It includes headers related to:

- **Core V8 concepts:** `objects.h`, `heap-object-inl.h`, `instance-type.h`, `map.h`
- **Javascript language features:**  `api/api.h`, `ast/ast.h`, `builtins/builtins.h`, `execution/execution.h`
- **Memory management:** `heap/heap-inl.h`, `heap/factory-inl.h`
- **Data structures:** `dictionary.h`, `hash-table-inl.h`
- **Various object types:** `js-array-inl.h`, `js-regexp-inl.h`, `promise.h`, `string-inl.h`

The code also defines various helper functions for object manipulation, type checking, and conversions.

**Key areas covered in this part:**

1. **Type System:** Definitions and manipulations related to `InstanceType`.
2. **Object Conversions:** Functions for converting Javascript values to various types (Number, String, Object, etc.) according to Javascript specifications (e.g., `ToObjectImpl`, `ConvertToNumber`, `ConvertToString`).
3. **Comparisons:**  Implementations of abstract and strict equality and relational comparisons (`Compare`, `Equals`, `StrictEquals`).
4. **Object Properties:** Functions for getting and setting object properties, including handling accessors and proxies (`GetProperty`, `SetPropertyWithAccessor`, `JSProxy::GetProperty`).
5. **"instanceof" operator:** Implementation of the `instanceof` operator (`InstanceOf`, `OrdinaryHasInstance`).
6. **Object Prototypes:** Functions for getting and working with prototypes (`GetPrototype`).
7. **Typeof Operator:** Implementation of the `typeof` operator.
8. **Hashing:**  Functions for obtaining object hashes (`GetOrCreateHash`, `GetSimpleHash`).
9. **SameValue and SameValueZero:** Implementations of these equality algorithms.
10. **Array-like Objects:**  Functions for working with array-like objects (`CreateListFromArrayLike`, `GetLengthFromArrayLike`).
11. **Error Handling:**  Usage of `THROW_NEW_ERROR`.
12. **Internal Utilities:**  Helper functions like `BooleanValue`, `NumberValue`.

Based on this analysis, the main function seems to be providing the foundational C++ implementations for core Javascript object operations and type conversions within the V8 engine.
这个C++源代码文件（`v8/src/objects/objects.cc`）是V8 JavaScript引擎中负责处理**JavaScript对象**的核心部分。 这是该文件的第一部分，主要功能是定义了与JavaScript对象相关的**基本操作、类型转换、比较以及属性访问机制**的C++实现。

具体来说，这部分代码的功能可以归纳为以下几点：

1. **定义和操作对象类型 (Instance Types):**  定义了V8内部表示不同JavaScript对象类型的枚举 (`InstanceType`)，并提供了将这些类型转换为字符串的辅助函数。

2. **实现JavaScript值的类型转换:**  提供了各种将JavaScript值转换为其他类型的方法，例如：
    - `ToObjectImpl`: 将值转换为对象。
    - `ConvertToNumber`: 将值转换为数字。
    - `ConvertToString`: 将值转换为字符串。
    - `ConvertToBoolean`: 将值转换为布尔值。
    - `ConvertToInt32`, `ConvertToUint32`, `ConvertToLength`, `ConvertToIndex`: 将值转换为特定类型的数字。
    - `ConvertToName`, `ConvertToPropertyKey`: 将值转换为属性键（字符串或Symbol）。

3. **实现JavaScript的比较操作:**  实现了抽象相等比较 (`Equals`)、严格相等比较 (`StrictEquals`) 和关系比较 (`Compare`) 的逻辑。

4. **实现 `typeof` 运算符:**  提供了确定JavaScript值类型的 `TypeOf` 函数。

5. **实现 `instanceof` 运算符:**  实现了 `InstanceOf` 和 `OrdinaryHasInstance` 函数，用于判断对象是否为某个构造函数的实例。

6. **实现属性访问机制:**  提供了 `GetProperty` 和 `SetPropertyWithAccessor` 等函数，用于获取和设置对象的属性，包括处理访问器属性 (getters/setters) 和代理对象 (Proxies)。

7. **处理代理对象 (Proxies):**  包含了 `JSProxy::GetProperty` 等函数，实现了对代理对象的属性访问拦截器的调用和结果校验。

8. **提供辅助函数:**  包含了一些辅助函数，如 `BooleanValue`（获取值的布尔值）、`NumberValue`（获取值的数值）、`SameValue` 和 `SameValueZero`（判断两个值是否相同）。

**与JavaScript功能的关联和示例：**

这部分 C++ 代码直接支撑着许多基础的 JavaScript 语法和操作。以下是一些与上述功能对应的 JavaScript 示例：

1. **类型转换:**
   ```javascript
   console.log(typeof 123); // "number" (C++ 中 InstanceType 的体现)
   console.log(Number("456")); // 456 (C++ 中 ConvertToNumber 的体现)
   console.log(String(true)); // "true" (C++ 中 ConvertToString 的体现)
   console.log(!!0); // false (C++ 中 ConvertToBoolean 的体现)
   ```

2. **比较操作:**
   ```javascript
   console.log(1 == "1"); // true (C++ 中 Equals 的体现)
   console.log(1 === "1"); // false (C++ 中 StrictEquals 的体现)
   console.log(5 > 3);    // true (C++ 中 Compare 的体现)
   ```

3. **`typeof` 运算符:**
   ```javascript
   console.log(typeof {});   // "object" (C++ 中 TypeOf 的体现)
   console.log(typeof null); // "object" (C++ 中 TypeOf 的体现)
   console.log(typeof function(){}); // "function" (C++ 中 TypeOf 的体现)
   ```

4. **`instanceof` 运算符:**
   ```javascript
   class MyClass {}
   const obj = new MyClass();
   console.log(obj instanceof MyClass); // true (C++ 中 InstanceOf 的体现)
   console.log(obj instanceof Object);  // true (C++ 中 OrdinaryHasInstance 的体现)
   ```

5. **属性访问:**
   ```javascript
   const myObject = { name: "Alice", age: 30 };
   console.log(myObject.name); // "Alice" (C++ 中 GetProperty 的体现)

   const myProxy = new Proxy({}, {
       get(target, prop) {
           console.log(`Getting property: ${prop}`);
           return target[prop];
       }
   });
   myProxy.foo; // "Getting property: foo" (C++ 中 JSProxy::GetProperty 的体现)
   ```

总之，`objects.cc` 的第一部分是 V8 引擎中关于 JavaScript 对象的核心实现，它为 JavaScript 语言中涉及对象的基本操作和类型转换提供了底层的 C++ 支持。

### 提示词
```
这是目录为v8/src/objects/objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```
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
        return Just(false);
      }
    } else if (IsSymbol(*x)) {
      if (IsSymbol(*y)) {
        return Just(x.is_identical_to(y));
      } else if (IsJSReceiver(*y)) {
        if (!JSReceiver::ToPrimitive(isolate, Cast<JSReceiver>(y))
                 .ToHandle(&y)) {
          return Nothing<bool>();
        }
      } else {
        return Just(false);
      }
    } else if (IsBigInt(*x)) {
      if (IsBigInt(*y)) {
        return Just(BigInt::EqualToBigInt(Cast<BigInt>(*x), Cast<BigInt>(*y)));
      }
      return Equals(isolate, y, x);
    } else if (IsJSReceiver(*x)) {
      if (IsJSReceiver(*y)) {
        return Just(x.is_identical_to(y));
      } else if (IsUndetectable(*y)) {
        return Just(IsUndetectable(*x));
      } else if (IsBoolean(*y)) {
        y = Oddball::ToNumber(isolate, Cast<Oddball>(y));
      } else if (!JSReceiver::ToPrimitive(isolate, Cast<JSReceiver>(x))
                      .ToHandle(&x)) {
        return Nothing<bool>();
      }
    } else {
      return Just(IsUndetectable(*x) && IsUndetectable(*y));
    }
  }
}

// static
bool Object::StrictEquals(Tagged<Object> obj, Tagged<Object> that) {
  if (IsNumber(obj)) {
    if (!IsNumber(that)) return false;
    return StrictNumberEquals(Cast<Number>(obj), Cast<Number>(that));
  } else if (IsString(obj)) {
    if (!IsString(that)) return false;
    return Cast<String>(obj)->Equals(Cast<String>(that));
  } else if (IsBigInt(obj)) {
    if (!IsBigInt(that)) return false;
    return BigInt::EqualToBigInt(Cast<BigInt>(obj), Cast<BigInt>(that));
  }
  return obj == that;
}

// static
Handle<String> Object::TypeOf(Isolate* isolate, DirectHandle<Object> object) {
  if (IsNumber(*object)) return isolate->factory()->number_string();
  if (IsOddball(*object))
    return handle(Cast<Oddball>(*object)->type_of(), isolate);
  if (IsUndetectable(*object)) {
    return isolate->factory()->undefined_string();
  }
  if (IsString(*object)) return isolate->factory()->string_string();
  if (IsSymbol(*object)) return isolate->factory()->symbol_string();
  if (IsBigInt(*object)) return isolate->factory()->bigint_string();
  if (IsCallable(*object)) return isolate->factory()->function_string();
  return isolate->factory()->object_string();
}

// static
MaybeHandle<Object> Object::Add(Isolate* isolate, Handle<Object> lhs,
                                Handle<Object> rhs) {
  if (IsNumber(*lhs) && IsNumber(*rhs)) {
    return isolate->factory()->NewNumber(
        Object::NumberValue(Cast<Number>(*lhs)) +
        Object::NumberValue(Cast<Number>(*rhs)));
  } else if (IsString(*lhs) && IsString(*rhs)) {
    return isolate->factory()->NewConsString(Cast<String>(lhs),
                                             Cast<String>(rhs));
  }
  ASSIGN_RETURN_ON_EXCEPTION(isolate, lhs, Object::ToPrimitive(isolate, lhs));
  ASSIGN_RETURN_ON_EXCEPTION(isolate, rhs, Object::ToPrimitive(isolate, rhs));
  if (IsString(*lhs) || IsString(*rhs)) {
    ASSIGN_RETURN_ON_EXCEPTION(isolate, rhs, Object::ToString(isolate, rhs));
    ASSIGN_RETURN_ON_EXCEPTION(isolate, lhs, Object::ToString(isolate, lhs));
    return isolate->factory()->NewConsString(Cast<String>(lhs),
                                             Cast<String>(rhs));
  }
  Handle<Number> lhs_number;
  Handle<Number> rhs_number;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, rhs_number,
                             Object::ToNumber(isolate, rhs));
  ASSIGN_RETURN_ON_EXCEPTION(isolate, lhs_number,
                             Object::ToNumber(isolate, lhs));
  return isolate->factory()->NewNumber(Object::NumberValue(*lhs_number) +
                                       Object::NumberValue(*rhs_number));
}

// static
MaybeHandle<Object> Object::OrdinaryHasInstance(Isolate* isolate,
                                                Handle<JSAny> callable,
                                                Handle<JSAny> object) {
  // The {callable} must have a [[Call]] internal method.
  if (!IsCallable(*callable)) return isolate->factory()->false_value();

  // Check if {callable} is a bound function, and if so retrieve its
  // [[BoundTargetFunction]] and use that instead of {callable}.
  if (IsJSBoundFunction(*callable)) {
    // Since there is a mutual recursion here, we might run out of stack
    // space for long chains of bound functions.
    STACK_CHECK(isolate, MaybeHandle<Object>());
    Handle<JSCallable> bound_callable(
        Cast<JSBoundFunction>(callable)->bound_target_function(), isolate);
    return Object::InstanceOf(isolate, object, bound_callable);
  }

  // If {object} is not a receiver, return false.
  if (!IsJSReceiver(*object)) return isolate->factory()->false_value();

  // Get the "prototype" of {callable}; raise an error if it's not a receiver.
  Handle<Object> prototype;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, prototype,
      Object::GetProperty(isolate, callable,
                          isolate->factory()->prototype_string()));
  if (!IsJSReceiver(*prototype)) {
    THROW_NEW_ERROR(
        isolate,
        NewTypeError(MessageTemplate::kInstanceofNonobjectProto, prototype));
  }

  // Return whether or not {prototype} is in the prototype chain of {object}.
  Maybe<bool> result = JSReceiver::HasInPrototypeChain(
      isolate, Cast<JSReceiver>(object), prototype);
  if (result.IsNothing()) return MaybeHandle<Object>();
  return isolate->factory()->ToBoolean(result.FromJust());
}

// static
MaybeHandle<Object> Object::InstanceOf(Isolate* isolate, Handle<JSAny> object,
                                       Handle<JSAny> callable) {
  // The {callable} must be a receiver.
  if (!IsJSReceiver(*callable)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kNonObjectInInstanceOfCheck));
  }

  // Lookup the @@hasInstance method on {callable}.
  Handle<Object> inst_of_handler;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, inst_of_handler,
      Object::GetMethod(isolate, Cast<JSReceiver>(callable),
                        isolate->factory()->has_instance_symbol()));
  if (!IsUndefined(*inst_of_handler, isolate)) {
    // Call the {inst_of_handler} on the {callable}.
    Handle<Object> result;
    Handle<Object> args[] = {object};
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, result,
        Execution::Call(isolate, inst_of_handler, callable, 1, args));
    return isolate->factory()->ToBoolean(
        Object::BooleanValue(*result, isolate));
  }

  // The {callable} must have a [[Call]] internal method.
  if (!IsCallable(*callable)) {
    THROW_NEW_ERROR(
        isolate, NewTypeError(MessageTemplate::kNonCallableInInstanceOfCheck));
  }

  // Fall back to OrdinaryHasInstance with {callable} and {object}.
  Handle<Object> result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result, Object::OrdinaryHasInstance(isolate, callable, object));
  return result;
}

// static
MaybeHandle<Object> Object::GetMethod(Isolate* isolate,
                                      Handle<JSReceiver> receiver,
                                      Handle<Name> name) {
  Handle<Object> func;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, func,
                             JSReceiver::GetProperty(isolate, receiver, name));
  if (IsNullOrUndefined(*func, isolate)) {
    return isolate->factory()->undefined_value();
  }
  if (!IsCallable(*func)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kPropertyNotFunction,
                                          func, name, receiver));
  }
  return func;
}

namespace {

MaybeHandle<FixedArray> CreateListFromArrayLikeFastPath(
    Isolate* isolate, Handle<Object> object, ElementTypes element_types) {
  if (element_types == ElementTypes::kAll) {
    if (IsJSArray(*object)) {
      Handle<JSArray> array = Cast<JSArray>(object);
      uint32_t length;
      if (!array->HasArrayPrototype(isolate) ||
          !Object::ToUint32(array->length(), &length) ||
          !array->HasFastElements() ||
          !JSObject::PrototypeHasNoElements(isolate, *array)) {
        return MaybeHandle<FixedArray>();
      }
      return array->GetElementsAccessor()->CreateListFromArrayLike(
          isolate, array, length);
    } else if (IsJSTypedArray(*object)) {
      Handle<JSTypedArray> array = Cast<JSTypedArray>(object);
      size_t length = array->GetLength();
      if (array->IsDetachedOrOutOfBounds() ||
          length > static_cast<size_t>(FixedArray::kMaxLength)) {
        return MaybeHandle<FixedArray>();
      }
      static_assert(FixedArray::kMaxLength <=
                    std::numeric_limits<uint32_t>::max());
      return array->GetElementsAccessor()->CreateListFromArrayLike(
          isolate, array, static_cast<uint32_t>(length));
    }
  }
  return MaybeHandle<FixedArray>();
}

}  // namespace

// static
MaybeHandle<FixedArray> Object::CreateListFromArrayLike(
    Isolate* isolate, Handle<Object> object, ElementTypes element_types) {
  // Fast-path for JSArray and JSTypedArray.
  MaybeHandle<FixedArray> fast_result =
      CreateListFromArrayLikeFastPath(isolate, object, element_types);
  if (!fast_result.is_null()) return fast_result;
  // 1. ReturnIfAbrupt(object).
  // 2. (default elementTypes -- not applicable.)
  // 3. If Type(obj) is not Object, throw a TypeError exception.
  if (!IsJSReceiver(*object)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kCalledOnNonObject,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     "CreateListFromArrayLike")));
  }

  // 4. Let len be ? ToLength(? Get(obj, "length")).
  Handle<JSReceiver> receiver = Cast<JSReceiver>(object);
  Handle<Object> raw_length_number;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, raw_length_number,
                             Object::GetLengthFromArrayLike(isolate, receiver));
  uint32_t len;
  if (!Object::ToUint32(*raw_length_number, &len) ||
      len > static_cast<uint32_t>(FixedArray::kMaxLength)) {
    THROW_NEW_ERROR(isolate,
                    NewRangeError(MessageTemplate::kInvalidArrayLength));
  }
  // 5. Let list be an empty List.
  Handle<FixedArray> list = isolate->factory()->NewFixedArray(len);
  // 6. Let index be 0.
  // 7. Repeat while index < len:
  for (uint32_t index = 0; index < len; ++index) {
    // 7a. Let indexName be ToString(index).
    // 7b. Let next be ? Get(obj, indexName).
    Handle<Object> next;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, next, JSReceiver::GetElement(isolate, receiver, index));
    switch (element_types) {
      case ElementTypes::kAll:
        // Nothing to do.
        break;
      case ElementTypes::kStringAndSymbol: {
        // 7c. If Type(next) is not an element of elementTypes, throw a
        //     TypeError exception.
        if (!IsName(*next)) {
          THROW_NEW_ERROR(
              isolate, NewTypeError(MessageTemplate::kNotPropertyName, next));
        }
        // 7d. Append next as the last element of list.
        // Internalize on the fly so we can use pointer identity later.
        next = isolate->factory()->InternalizeName(Cast<Name>(next));
        break;
      }
    }
    list->set(index, *next);
    // 7e. Set index to index + 1. (See loop header.)
  }
  // 8. Return list.
  return list;
}

// static
MaybeHandle<Object> Object::GetLengthFromArrayLike(Isolate* isolate,
                                                   Handle<JSReceiver> object) {
  Handle<Object> val;
  Handle<Name> key = isolate->factory()->length_string();
  ASSIGN_RETURN_ON_EXCEPTION(isolate, val,
                             JSReceiver::GetProperty(isolate, object, key));
  return Object::ToLength(isolate, val);
}

// static
MaybeHandle<Object> Object::GetProperty(LookupIterator* it,
                                        bool is_global_reference) {
  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::TRANSITION:
        UNREACHABLE();
      case LookupIterator::JSPROXY: {
        bool was_found;
        Handle<JSAny> receiver = it->GetReceiver();
        // In case of global IC, the receiver is the global object. Replace by
        // the global proxy.
        if (IsJSGlobalObject(*receiver)) {
          receiver = handle(Cast<JSGlobalObject>(*receiver)->global_proxy(),
                            it->isolate());
        }
        if (is_global_reference) {
          Maybe<bool> maybe = JSProxy::HasProperty(
              it->isolate(), it->GetHolder<JSProxy>(), it->GetName());
          if (maybe.IsNothing()) return {};
          if (!maybe.FromJust()) {
            it->NotFound();
            return it->isolate()->factory()->undefined_value();
          }
        }
        MaybeHandle<JSAny> result =
            JSProxy::GetProperty(it->isolate(), it->GetHolder<JSProxy>(),
                                 it->GetName(), receiver, &was_found);
        if (!was_found && !is_global_reference) it->NotFound();
        return result;
      }
      case LookupIterator::WASM_OBJECT:
        return it->isolate()->factory()->undefined_value();
      case LookupIterator::INTERCEPTOR: {
        bool done;
        Handle<JSAny> result;
        ASSIGN_RETURN_ON_EXCEPTION(
            it->isolate(), result,
            JSObject::GetPropertyWithInterceptor(it, &done));
        if (done) return result;
        continue;
      }
      case LookupIterator::ACCESS_CHECK:
        if (it->HasAccess()) continue;
        return JSObject::GetPropertyWithFailedAccessCheck(it);
      case LookupIterator::ACCESSOR:
        return GetPropertyWithAccessor(it);
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
        return it->isolate()->factory()->undefined_value();
      case LookupIterator::DATA:
        return it->GetDataValue();
      case LookupIterator::NOT_FOUND:
        if (it->IsPrivateName()) {
          auto private_symbol = Cast<Symbol>(it->name());
          Handle<String> name_string(
              Cast<String>(private_symbol->description()), it->isolate());
          if (private_symbol->is_private_brand()) {
            Handle<String> class_name =
                (name_string->length() == 0)
                    ? it->isolate()->factory()->anonymous_string()
                    : name_string;
            THROW_NEW_ERROR(
                it->isolate(),
                NewTypeError(MessageTemplate::kInvalidPrivateBrandInstance,
                             class_name));
          }
          THROW_NEW_ERROR(
              it->isolate(),
              NewTypeError(MessageTemplate::kInvalidPrivateMemberRead,
                           name_string));
        }

        return it->isolate()->factory()->undefined_value();
    }
    UNREACHABLE();
  }
}

// static
MaybeHandle<JSAny> JSProxy::GetProperty(Isolate* isolate,
                                        DirectHandle<JSProxy> proxy,
                                        Handle<Name> name,
                                        Handle<JSAny> receiver,
                                        bool* was_found) {
  *was_found = true;

  DCHECK(!name->IsPrivate());
  STACK_CHECK(isolate, kNullMaybeHandle);
  Handle<Name> trap_name = isolate->factory()->get_string();
  // 1. Assert: IsPropertyKey(P) is true.
  // 2. Let handler be the value of the [[ProxyHandler]] internal slot of O.
  Handle<UnionOf<JSReceiver, Null>> handler(proxy->handler(), isolate);
  // 3. If handler is null, throw a TypeError exception.
  // 4. Assert: Type(handler) is Object.
  if (proxy->IsRevoked()) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kProxyRevoked, trap_name));
  }
  // 5. Let target be the value of the [[ProxyTarget]] internal slot of O.
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate);
  // 6. Let trap be ? GetMethod(handler, "get").
  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, trap,
      Object::GetMethod(isolate, Cast<JSReceiver>(handler), trap_name));
  // 7. If trap is undefined, then
  if (IsUndefined(*trap, isolate)) {
    // 7.a Return target.[[Get]](P, Receiver).
    PropertyKey key(isolate, name);
    LookupIterator it(isolate, receiver, key, target);
    MaybeHandle<JSAny> result = Cast<JSAny>(Object::GetProperty(&it));
    *was_found = it.IsFound();
    return result;
  }
  // 8. Let trapResult be ? Call(trap, handler, «target, P, Receiver»).
  Handle<Object> trap_result;
  Handle<Object> args[] = {target, name, receiver};
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, trap_result,
      Execution::Call(isolate, trap, handler, arraysize(args), args));

  MaybeHandle<JSAny> result =
      JSProxy::CheckGetSetTrapResult(isolate, name, target, trap_result, kGet);
  if (result.is_null()) {
    return result;
  }

  // 11. Return trap_result
  return Cast<JSAny>(trap_result);
}

// static
MaybeHandle<JSAny> JSProxy::CheckGetSetTrapResult(Isolate* isolate,
                                                  Handle<Name> name,
                                                  Handle<JSReceiver> target,
                                                  Handle<Object> trap_result,
                                                  AccessKind access_kind) {
  // 9. Let targetDesc be ? target.[[GetOwnProperty]](P).
  PropertyDescriptor target_desc;
  Maybe<bool> target_found =
      JSReceiver::GetOwnPropertyDescriptor(isolate, target, name, &target_desc);
  MAYBE_RETURN_NULL(target_found);
  // 10. If targetDesc is not undefined, then
  if (target_found.FromJust()) {
    // 10.a. If IsDataDescriptor(targetDesc) and targetDesc.[[Configurable]] is
    //       false and targetDesc.[[Writable]] is false, then
    // 10.a.i. If SameValue(trapResult, targetDesc.[[Value]]) is false,
    //        throw a TypeError exception.
    bool inconsistent = PropertyDescriptor::IsDataDescriptor(&target_desc) &&
                        !target_desc.configurable() &&
                        !target_desc.writable() &&
                        !Object::SameValue(*trap_result, *target_desc.value());
    if (inconsistent) {
      if (access_kind == kGet) {
        THROW_NEW_ERROR(
            isolate, NewTypeError(MessageTemplate::kProxyGetNonConfigurableData,
                                  name, target_desc.value(), trap_result));
      } else {
        isolate->Throw(*isolate->factory()->NewTypeError(
            MessageTemplate::kProxySetFrozenData, name));
        return {};
      }
    }
    // 10.b. If IsAccessorDescriptor(targetDesc) and targetDesc.[[Configurable]]
    //       is false and targetDesc.[[Get]] is undefined, then
    // 10.b.i. If trapResult is not undefined, throw a TypeError exception.
    if (access_kind == kGet) {
      inconsistent = PropertyDescriptor::IsAccessorDescriptor(&target_desc) &&
                     !target_desc.configurable() &&
                     IsUndefined(*target_desc.get(), isolate) &&
                     !IsUndefined(*trap_result, isolate);
    } else {
      inconsistent = PropertyDescriptor::IsAccessorDescriptor(&target_desc) &&
                     !target_desc.configurable() &&
                     IsUndefined(*target_desc.set(), isolate);
    }
    if (inconsistent) {
      if (access_kind == kGet) {
        THROW_NEW_ERROR(
            isolate,
            NewTypeError(MessageTemplate::kProxyGetNonConfigurableAccessor,
                         name, trap_result));
      } else {
        isolate->Throw(*isolate->factory()->NewTypeError(
            MessageTemplate::kProxySetFrozenAccessor, name));
        return {};
      }
    }
  }
  return isolate->factory()->undefined_value();
}

// static
bool Object::ToInt32(Tagged<Object> obj, int32_t* value) {
  if (IsSmi(obj)) {
    *value = Smi::ToInt(obj);
    return true;
  }
  if (IsHeapNumber(obj)) {
    double num = Cast<HeapNumber>(obj)->value();
    // Check range before conversion to avoid undefined behavior.
    if (num >= kMinInt && num <= kMaxInt && FastI2D(FastD2I(num)) == num) {
      *value = FastD2I(num);
      return true;
    }
  }
  return false;
}

// ES6 9.5.1
// static
MaybeHandle<JSPrototype> JSProxy::GetPrototype(DirectHandle<JSProxy> proxy) {
  Isolate* isolate = proxy->GetIsolate();
  Handle<String> trap_name = isolate->factory()->getPrototypeOf_string();

  STACK_CHECK(isolate, {});

  // 1. Let handler be the value of the [[ProxyHandler]] internal slot.
  // 2. If handler is null, throw a TypeError exception.
  // 3. Assert: Type(handler) is Object.
  // 4. Let target be the value of the [[ProxyTarget]] internal slot.
  if (proxy->IsRevoked()) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kProxyRevoked, trap_name));
  }
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate);
  Handle<JSReceiver> handler(Cast<JSReceiver>(proxy->handler()), isolate);

  // 5. Let trap be ? GetMethod(handler, "getPrototypeOf").
  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, trap,
                             Object::GetMethod(isolate, handler, trap_name));
  // 6. If trap is undefined, then return target.[[GetPrototypeOf]]().
  if (IsUndefined(*trap, isolate)) {
    return JSReceiver::GetPrototype(isolate, target);
  }
  // 7. Let handlerProto be ? Call(trap, handler, «target»).
  Handle<Object> argv[] = {target};
  Handle<Object> handler_proto_result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, handler_proto_result,
      Execution::Call(isolate, trap, handler, arraysize(argv), argv));
  // 8. If Type(handlerProto) is neither Object nor Null, throw a TypeError.
  Handle<JSPrototype> handler_proto;
  if (!TryCast(handler_proto_result, &handler_proto)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kProxyGetPrototypeOfInvalid));
  }
  // 9. Let extensibleTarget be ? IsExtensible(target).
  Maybe<bool> is_extensible = JSReceiver::IsExtensible(isolate, target);
  MAYBE_RETURN(is_extensible, {});
  // 10. If extensibleTarget is true, return handlerProto.
  if (is_extensible.FromJust()) return handler_proto;
  // 11. Let targetProto be ? target.[[GetPrototypeOf]]().
  Handle<JSPrototype> target_proto;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, target_proto,
                             JSReceiver::GetPrototype(isolate, target));
  // 12. If SameValue(handlerProto, targetProto) is false, throw a TypeError.
  if (!Object::SameValue(*handler_proto, *target_proto)) {
    THROW_NEW_ERROR(
        isolate,
        NewTypeError(MessageTemplate::kProxyGetPrototypeOfNonExtensible));
  }
  // 13. Return handlerProto.
  return handler_proto;
}

MaybeHandle<JSAny> Object::GetPropertyWithAccessor(LookupIterator* it) {
  Isolate* isolate = it->isolate();
  Handle<Object> structure = it->GetAccessors();
  Handle<JSAny> receiver = it->GetReceiver();
  // In case of global IC, the receiver is the global object. Replace by the
  // global proxy.
  if (IsJSGlobalObject(*receiver)) {
    receiver = handle(Cast<JSGlobalObject>(*receiver)->global_proxy(), isolate);
  }

  // We should never get here to initialize a const with the hole value since a
  // const declaration would conflict with the getter.
  DCHECK(!IsForeign(*structure));

  // API style callbacks.
  Handle<JSObject> holder = it->GetHolder<JSObject>();
  if (IsAccessorInfo(*structure)) {
    Handle<Name> name = it->GetName();
    auto info = Cast<AccessorInfo>(structure);

    if (!info->has_getter(isolate)) {
      return isolate->factory()->undefined_value();
    }

    if (info->is_sloppy() && !IsJSReceiver(*receiver)) {
      ASSIGN_RETURN_ON_EXCEPTION(isolate, receiver,
                                 Object::ConvertReceiver(isolate, receiver));
    }

    PropertyCallbackArguments args(isolate, info->data(), *receiver, *holder,
                                   Just(kDontThrow));
    Handle<JSAny> result = args.CallAccessorGetter(info, name);
    RETURN_EXCEPTION_IF_EXCEPTION(isolate);
    Handle<JSAny> reboxed_result = handle(*result, isolate);
    if (info->replace_on_access() && IsJSReceiver(*receiver)) {
      RETURN_ON_EXCEPTION(isolate,
                          Accessors::ReplaceAccessorWithDataProperty(
                              isolate, receiver, holder, name, result));
    }
    return reboxed_result;
  }

  auto accessor_pair = Cast<AccessorPair>(structure);
  // AccessorPair with 'cached' private property.
  if (it->TryLookupCachedProperty(accessor_pair)) {
    return Cast<JSAny>(Object::GetProperty(it));
  }

  // Regular accessor.
  Handle<Object> getter(accessor_pair->getter(), isolate);
  if (IsFunctionTemplateInfo(*getter)) {
    SaveAndSwitchContext save(isolate, holder->GetCreationContext().value());
    return Cast<JSAny>(Builtins::InvokeApiFunction(
        isolate, false, Cast<FunctionTemplateInfo>(getter), receiver, 0,
        nullptr, isolate->factory()->undefined_value()));
  } else if (IsCallable(*getter)) {
    // TODO(rossberg): nicer would be to cast to some JSCallable here...
    return Object::GetPropertyWithDefinedGetter(receiver,
                                                Cast<JSReceiver>(getter));
  }
  // Getter is not a function.
  return isolate->factory()->undefined_value();
}

Maybe<bool> Object::SetPropertyWithAccessor(
    LookupIterator* it, Handle<Object> value,
    Maybe<ShouldThrow> maybe_should_throw) {
  Isolate* isolate = it->isolate();
  Handle<Object> structure = it->GetAccessors();
  Handle<JSAny> receiver = it->GetReceiver();
  // In case of global IC, the receiver is the global object. Replace by the
  // global proxy.
  if (IsJSGlobalObject(*receiver)) {
    receiver = handle(Cast<JSGlobalObject>(*receiver)->global_proxy(), isolate);
  }

  // We should never get here to initialize a const with the hole value since a
  // const declaration would conflict with the setter.
  DCHECK(!IsForeign(*structure));

  // API style callbacks.
  DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
  if (IsAccessorInfo(*structure)) {
    Handle<Name> name = it->GetName();
    auto info = Cast<AccessorInfo>(structure);

    if (!info->has_setter(isolate)) {
      // TODO(verwaest): We should not get here anymore once all AccessorInfos
      // are marked as special_data_property. They cannot both be writable and
      // not have a setter.
      return Just(true);
    }

    if (info->is_sloppy() && !IsJSReceiver(*receiver)) {
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, receiver, Object::ConvertReceiver(isolate, receiver),
          Nothing<bool>());
    }

    PropertyCallbackArguments args(isolate, info->data(), *receiver, *holder,
                                   maybe_should_throw);
    bool result = args.CallAccessorSetter(info, name, value);
    RETURN_VALUE_IF_EXCEPTION(isolate, Nothing<bool>());
    // Ensure the setter callback respects the "should throw" value - it's
    // allowed to fail without throwing only in case of kDontThrow.
    DCHECK_IMPLIES(!result,
                   GetShouldThrow(isolate, maybe_should_throw) == kDontThrow);
    return Just(result);
  }

  // Regular accessor.
  Handle<Object> setter(Cast<AccessorPair>(*structure)->setter(), isolate);
  if (IsFunctionTemplateInfo(*setter)) {
    SaveAndSwitchContext save(isolate, holder->GetCreationContext().value());
    Handle<Object> argv[] = {value};
    RETURN_ON_EXCEPTION_VALUE(
        isolate,
        Builtins::InvokeApiFunction(
            isolate, false, Cast<FunctionTemplateInfo>(setter), receiver,
            arraysize(argv), argv, isolate->factory()->undefined_value()),
        Nothing<bool>());
    return Just(true);
  } else if (IsCallable(*setter)) {
    // TODO(rossberg): nicer would be to cast to some JSCallable here...
    return SetPropertyWithDefinedSetter(receiver, Cast<JSReceiver>(setter),
                                        value, maybe_should_throw);
  }

  RETURN_FAILURE(isolate, GetShouldThrow(isolate, maybe_should_throw),
                 NewTypeError(MessageTemplate::kNoSetterInCallback,
                              it->GetName(), it->GetHolder<JSObject>()));
}

MaybeHandle<JSAny> Object::GetPropertyWithDefinedGetter(
    Handle<JSAny> receiver, Handle<JSReceiver> getter) {
  Isolate* isolate = getter->GetIsolate();

  // Platforms with simulators like arm/arm64 expose a funny issue. If the
  // simulator has a separate JS stack pointer from the C++ stack pointer, it
  // can miss C++ stack overflows in the stack guard at the start of JavaScript
  // functions. It would be very expensive to check the C++ stack pointer at
  // that location. The best solution seems to be to break the impasse by
  // adding checks at possible recursion points. What's more, we don't put
  // this stack check behind the USE_SIMULATOR define in order to keep
  // behavior the same between hardware and simulators.
  StackLimitCheck check(isolate);
  if (check.JsHasOverflowed()) {
    isolate->StackOverflow();
    return kNullMaybeHandle;
  }

  return Cast<JSAny>(Execution::Call(isolate, getter, receiver, 0, nullptr));
}

Maybe<bool> Object::SetPropertyWithDefinedSetter(
    Handle<JSAny> receiver, Handle<JSReceiver> setter, Handle<Object> value,
    Maybe<ShouldThrow> should_throw) {
  Isolate* isolate = setter->GetIsolate();

  Handle<Object> argv[] = {value};
  RETURN_ON_EXCEPTION_VALUE(
      isolate,
      Execution::Call(isolate, setter, receiver, arraysize(argv), argv),
      Nothing<bool>());
  return Just(true);
}

// static
Tagged<Map> Object::GetPrototypeChainRootMap(Tagged<Object> obj,
                                             Isolate* isolate) {
  DisallowGarbageCollection no_alloc;
  if (IsSmi(obj)) {
    Tagged<Context> native_context = isolate->context()->native_context();
    return native_context->number_function()->initial_map();
  }

  const Tagged<HeapObject> heap_object = Cast<HeapObject>(obj);
  return heap_object->map()->GetPrototypeChainRootMap(isolate);
}

// static
Tagged<Smi> Object::GetOrCreateHash(Tagged<Object> obj, Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  Tagged<Object> hash = Object::GetSimpleHash(obj);
  if (IsSmi(hash)) return Cast<Smi>(hash);

  DCHECK(IsJSReceiver(obj));
  return Cast<JSReceiver>(obj)->GetOrCreateIdentityHash(isolate);
}

// static
bool Object::SameValue(Tagged<Object> obj, Tagged<Object> other) {
  if (other == obj) return true;

  if (IsNumber(obj) && IsNumber(other)) {
    return SameNumberValue(Object::NumberValue(Cast<Number>(obj)),
                           Object::NumberValue(Cast<Number>(other)));
  }
  if (IsString(obj) && IsString(other)) {
    return Cast<String>(obj)->Equals(Cast<String>(other));
  }
  if (IsBigInt(obj) && IsBigInt(other)) {
    return BigInt::EqualToBigInt(Cast<BigInt>(obj), Cast<BigInt>(other));
  }
  return false;
}

// static
bool Object::SameValueZero(Tagged<Object> obj, Tagged<Object> other) {
  if (other == obj) return true;

  if (IsNumber(obj) && IsNumber(other)) {
    double this_value = Object::NumberValue(Cast<Number>(obj));
    double other_value = Object::NumberValue(Cast<Number>(other));
    // +0 == -0 is true
    return this_value == other_value ||
           (std::isnan(this_value) && std::isnan(other_value));
  }
  if (IsString(obj) && IsString(other)) {
    return Cast<String>(obj)->Equals(Cast<String>(other));
  }
  if (IsBigInt(obj) && IsBigInt(other)) {
    return BigInt::EqualToBigInt(Cast<BigInt>(obj), Cast<BigInt>(other));
  }
  return false;
}

MaybeHandle<Object> Object::ArraySpeciesConstructor(
    Isolate* isolate, Handle<JSAny> original_array) {
  Handle<Object> default_species = isolate->array_function();
  if (!v8_flags.builtin_subclassing) return default_species;
  if (IsJSArray(*original_array) &&
      Cast<JSArray>(original_array)->HasArrayPrototype(isolate) &&
      Protectors::IsArraySpeciesLookupChainIntact(isolate)) {
    return default_species;
  }
  Handle<Object> constructor = isolate->factory()->undefined_value();
  Maybe<bool> is_array = IsArray(original_array);
  MAYBE_RETURN_NULL(is_array);
  if (is_array.FromJust()) {
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, constructor,
        Object::GetProperty(isolate, original_array,
                            isolate->factory()->constructor_string()));
    if (IsConstructor(*constructor)) {
      Handle<NativeContext> constructor_context;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, constructor_context,
          JSReceiver::GetFunctionRealm(Cast<JSReceiver>(constructor)));
      if (*constructor_context != *isolate->native_context() &&
          *constructor == constructor_context->array_function()) {
        constructor = isolate->factory()->undefined_value();
      }
    }
    if (IsJSReceiver(*constructor)) {
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, constructor,
          JSReceiver::GetProperty(isolate, Cast<JSReceiver>(constructor),
                                  isolate->factory()->species_symbol()));
      if (IsNull(*constructor, isola
```