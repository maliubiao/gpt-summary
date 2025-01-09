Response:
Let's break down the thought process for analyzing this V8 source code snippet.

**1. Initial Understanding & Context:**

* **File Path:**  `v8/src/builtins/builtins-intl.cc` immediately tells us this is part of V8's built-in functions, specifically related to internationalization (`intl`). The `.cc` extension indicates C++ source code.
* **Copyright & License:** Standard boilerplate, but reinforces that this is official V8 code.
* **`#ifndef V8_INTL_SUPPORT`:** This is crucial. It means the entire file is *only* compiled if internationalization support is enabled in the V8 build. This implies the file's purpose is entirely about providing Intl functionality.
* **Includes:**  A quick scan of the `#include` statements reveals the key areas this file interacts with:
    * Core V8 builtins (`builtins-utils-inl.h`, `builtins.h`)
    * Date handling (`date/date.h`)
    * Internal V8 object representations (various `src/objects/...`)
    * Logging and counters (`logging/counters.h`)
    * Unicode support (`unicode/brkiter.h`) - This strongly reinforces the internationalization focus.

**2. Identifying Key Patterns & Functionality:**

* **`BUILTIN(...)` Macros:**  These are the most important. They define the entry points for JavaScript Intl API calls into the V8 C++ implementation. Each `BUILTIN` corresponds to a specific JavaScript method or constructor. Listing these out is the first step in understanding the file's functions.

* **Intl API Coverage:**  As I list the `BUILTIN`s, I start recognizing the familiar Intl API names:
    * `String.prototype.toUpperCaseIntl`, `String.prototype.normalizeIntl`, `String.prototype.localeCompareIntl`
    * `Intl.NumberFormat`, `Intl.DateTimeFormat`, `Intl.ListFormat`, `Intl.Locale`, `Intl.RelativeTimeFormat`, `Intl.DisplayNames`, `Intl.DurationFormat`, `Intl.Segmenter`, `Intl.v8BreakIterator`
    *  Methods like `supportedLocalesOf`, `resolvedOptions`, `format`, `formatToParts`, `formatRange`, `formatRangeToParts`, `maximize`, `minimize`, and specific getter methods on `Intl.Locale`.

* **Common Helper Functions/Templates:**  I notice patterns like `LegacyFormatConstructor`, `DisallowCallConstructor`, `CallOrConstructConstructor`, and the `DateTimeFormatRange` and `NumberFormatRange` templates. These suggest code reuse and common patterns for implementing Intl constructors and methods. The template arguments hint at the types involved (like `JSNumberFormat`, `JSDateTimeFormat`).

* **Error Handling:**  The code frequently uses `RETURN_RESULT_OR_FAILURE`, `THROW_NEW_ERROR_RETURN_FAILURE`, and `CHECK_RECEIVER`. This indicates careful error handling and type checking, which is crucial for built-in APIs. The error messages (like `kIncompatibleMethodReceiver`, `kInvalidTimeValue`, `kConstructorNotFunction`) give clues about common misuse scenarios.

* **Locale Handling:** The presence of functions like `Intl::SupportedLocalesOf`, `Intl::GetCanonicalLocales`, and the various `Intl.Locale` prototype methods points to the core role of locale management in this code.

**3. Answering the Specific Questions:**

* **Functionality:** Based on the identified `BUILTIN`s and the included headers, it's clear the file implements the core functionality of the JavaScript Intl API within V8.

* **`.tq` Extension:** The code is `.cc`, so it's C++, not Torque.

* **Relationship to JavaScript:** The `BUILTIN` macros directly link C++ functions to JavaScript methods. The examples I generate will use the corresponding JavaScript Intl API.

* **Code Logic Inference:**  The helper functions and templates suggest a pattern:
    1. Check receiver type (`CHECK_RECEIVER`).
    2. Unwrap internal Intl object (`JSNumberFormat::UnwrapNumberFormat`, etc.).
    3. Perform core Intl operation (often delegated to the `src/objects/intl-objects.h` classes).
    4. Handle potential errors.
    5. Return the result.
    The `DateTimeFormatRange` and `NumberFormatRange` templates show a pattern for handling date/number ranges.

* **Assumptions, Inputs, and Outputs:**  For a specific `BUILTIN`, I can make assumptions about the input arguments based on the JavaScript API definition and deduce the likely output type.

* **Common Programming Errors:**  The error handling in the code itself provides hints. Trying to call an Intl constructor without `new`, or passing incorrect types to methods, are likely errors.

* **Summary:** Combine all the observations to provide a concise overview of the file's purpose.

**4. Iteration and Refinement:**

My initial analysis might be broad. I would then refine it by:

* **Grouping related functionalities:**  For example, grouping all the `Intl.NumberFormat` related `BUILTIN`s together.
* **Looking for dependencies:**  How do these C++ functions interact with the `src/objects` classes? (Though the provided snippet doesn't show the details of those classes.)
* **Considering performance implications:**  While not explicitly requested, I might note that this code is performance-critical as it's part of the core JavaScript engine.

By following these steps, I can systematically analyze the C++ code and extract its key functionalities, its relationship to JavaScript, and potential usage patterns and pitfalls.
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_INTL_SUPPORT
#error Internationalization is expected to be enabled.
#endif  // V8_INTL_SUPPORT

#include <cmath>
#include <list>
#include <memory>

#include "src/builtins/builtins-utils-inl.h"
#include "src/builtins/builtins.h"
#include "src/date/date.h"
#include "src/logging/counters.h"
#include "src/objects/elements.h"
#include "src/objects/intl-objects.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-break-iterator-inl.h"
#include "src/objects/js-collator-inl.h"
#include "src/objects/js-date-time-format-inl.h"
#include "src/objects/js-display-names-inl.h"
#include "src/objects/js-duration-format-inl.h"
#include "src/objects/js-list-format-inl.h"
#include "src/objects/js-locale-inl.h"
#include "src/objects/js-number-format-inl.h"
#include "src/objects/js-plural-rules-inl.h"
#include "src/objects/js-relative-time-format-inl.h"
#include "src/objects/js-segment-iterator-inl.h"
#include "src/objects/js-segmenter-inl.h"
#include "src/objects/js-segments-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/option-utils.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/smi.h"
#include "unicode/brkiter.h"

namespace v8 {
namespace internal {

BUILTIN(StringPrototypeToUpperCaseIntl) {
  HandleScope scope(isolate);
  TO_THIS_STRING(string, "String.prototype.toUpperCase");
  string = String::Flatten(isolate, string);
  RETURN_RESULT_OR_FAILURE(isolate, Intl::ConvertToUpper(isolate, string));
}

BUILTIN(StringPrototypeNormalizeIntl) {
  HandleScope handle_scope(isolate);
  isolate->CountUsage(v8::Isolate::UseCounterFeature::kStringNormalize);
  TO_THIS_STRING(string, "String.prototype.normalize");

  Handle<Object> form_input = args.atOrUndefined(isolate, 1);

  RETURN_RESULT_OR_FAILURE(isolate,
                           Intl::Normalize(isolate, string, form_input));
}

// ecma402 #sup-properties-of-the-string-prototype-object
// ecma402 section 19.1.1.
//   String.prototype.localeCompare ( that [ , locales [ , options ] ] )
// This implementation supersedes the definition provided in ES6.
BUILTIN(StringPrototypeLocaleCompareIntl) {
  HandleScope handle_scope(isolate);

  isolate->CountUsage(v8::Isolate::UseCounterFeature::kStringLocaleCompare);
  static const char* const kMethod = "String.prototype.localeCompare";

  TO_THIS_STRING(str1, kMethod);
  Handle<String> str2;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, str2, Object::ToString(isolate, args.atOrUndefined(isolate, 1)));
  std::optional<int> result = Intl::StringLocaleCompare(
      isolate, str1, str2, args.atOrUndefined(isolate, 2),
      args.atOrUndefined(isolate, 3), kMethod);
  if (!result.has_value()) {
    DCHECK(isolate->has_exception());
    return ReadOnlyRoots(isolate).exception();
  }
  return Smi::FromInt(result.value());
}

BUILTIN(V8BreakIteratorSupportedLocalesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Intl::SupportedLocalesOf(
                   isolate, "Intl.v8BreakIterator.supportedLocalesOf",
                   JSV8BreakIterator::GetAvailableLocales(), locales, options));
}

BUILTIN(NumberFormatSupportedLocalesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Intl::SupportedLocalesOf(
                   isolate, "Intl.NumberFormat.supportedLocalesOf",
                   JSNumberFormat::GetAvailableLocales(), locales, options));
}

BUILTIN(NumberFormatPrototypeFormatToParts) {
  const char* const method_name = "Intl.NumberFormat.prototype.formatToParts";
  HandleScope handle_scope(isolate);
  CHECK_RECEIVER(JSNumberFormat, number_format, method_name);

  Handle<Object> x;
  if (args.length() >= 2) {
    x = args.at(1);
  } else {
    x = isolate->factory()->nan_value();
  }

  RETURN_RESULT_OR_FAILURE(
      isolate, JSNumberFormat::FormatToParts(isolate, number_format, x));
}

BUILTIN(DateTimeFormatPrototypeResolvedOptions) {
  const char* const method_name =
      "Intl.DateTimeFormat.prototype.resolvedOptions";
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSReceiver, format_holder, method_name);

  // 3. Let dtf be ? UnwrapDateTimeFormat(dtf).
  Handle<JSDateTimeFormat> date_time_format;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, date_time_format,
      JSDateTimeFormat::UnwrapDateTimeFormat(isolate, format_holder));

  RETURN_RESULT_OR_FAILURE(
      isolate, JSDateTimeFormat::ResolvedOptions(isolate, date_time_format));
}

BUILTIN(DateTimeFormatSupportedLocalesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Intl::SupportedLocalesOf(
                   isolate, "Intl.DateTimeFormat.supportedLocalesOf",
                   JSDateTimeFormat::GetAvailableLocales(), locales, options));
}

BUILTIN(DateTimeFormatPrototypeFormatToParts) {
  const char* const method_name = "Intl.DateTimeFormat.prototype.formatToParts";
  HandleScope handle_scope(isolate);
  CHECK_RECEIVER(JSObject, date_format_holder, method_name);
  Factory* factory = isolate->factory();

  if (!IsJSDateTimeFormat(*date_format_holder)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kIncompatibleMethodReceiver,
                              factory->NewStringFromAsciiChecked(method_name),
                              date_format_holder));
  }
  auto dtf = Cast<JSDateTimeFormat>(date_format_holder);

  Handle<Object> x = args.atOrUndefined(isolate, 1);
  RETURN_RESULT_OR_FAILURE(isolate, JSDateTimeFormat::FormatToParts(
                                        isolate, dtf, x, false, method_name));
}

// Common code for DateTimeFormatPrototypeFormtRange(|ToParts)
template <class T, MaybeHandle<T> (*F)(Isolate*, Handle<JSDateTimeFormat>,
                                       Handle<Object>, Handle<Object>,
                                       const char* const)>
V8_WARN_UNUSED_RESULT Tagged<Object> DateTimeFormatRange(
    BuiltinArguments args, Isolate* isolate, const char* const method_name) {
  // 1. Let dtf be this value.
  // 2. Perform ? RequireInternalSlot(dtf, [[InitializedDateTimeFormat]]).
  CHECK_RECEIVER(JSDateTimeFormat, dtf, method_name);

  // 3. If startDate is undefined or endDate is undefined, throw a TypeError
  // exception.
  Handle<Object> start_date = args.atOrUndefined(isolate, 1);
  Handle<Object> end_date = args.atOrUndefined(isolate, 2);
  if (IsUndefined(*start_date, isolate) || IsUndefined(*end_date, isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kInvalidTimeValue));
  }

  // 4. Return ? FormatDateTimeRange(dtf, startDate, endDate)
  // OR
  // 4. Return ? FormatDateTimeRangeToParts(dtf, startDate, endDate).
  RETURN_RESULT_OR_FAILURE(isolate,
                           F(isolate, dtf, start_date, end_date, method_name));
}

BUILTIN(DateTimeFormatPrototypeFormatRange) {
  const char* const method_name = "Intl.DateTimeFormat.prototype.formatRange";
  HandleScope handle_scope(isolate);
  return DateTimeFormatRange<String, JSDateTimeFormat::FormatRange>(
      args, isolate, method_name);
}

BUILTIN(DateTimeFormatPrototypeFormatRangeToParts) {
  const char* const method_name =
      "Intl.DateTimeFormat.prototype.formatRangeToParts";
  HandleScope handle_scope(isolate);
  return DateTimeFormatRange<JSArray, JSDateTimeFormat::FormatRangeToParts>(
      args, isolate, method_name);
}

namespace {

Handle<JSFunction> CreateBoundFunction(Isolate* isolate,
                                       DirectHandle<JSObject> object,
                                       Builtin builtin, int len) {
  DirectHandle<NativeContext> native_context(
      isolate->context()->native_context(), isolate);
  Handle<Context> context = isolate->factory()->NewBuiltinContext(
      native_context,
      static_cast<int>(Intl::BoundFunctionContextSlot::kLength));

  context->set(static_cast<int>(Intl::BoundFunctionContextSlot::kBoundFunction),
               *object);

  Handle<SharedFunctionInfo> info =
      isolate->factory()->NewSharedFunctionInfoForBuiltin(
          isolate->factory()->empty_string(), builtin, len, kAdapt);

  return Factory::JSFunctionBuilder{isolate, info, context}
      .set_map(isolate->strict_function_without_prototype_map())
      .Build();
}

/**
 * Common code shared between DateTimeFormatConstructor and
 * NumberFormatConstrutor
 */
template <class T>
Tagged<Object> LegacyFormatConstructor(BuiltinArguments args, Isolate* isolate,
                                       v8::Isolate::UseCounterFeature feature,
                                       Handle<JSAny> constructor,
                                       const char* method_name) {
  isolate->CountUsage(feature);
  Handle<JSReceiver> new_target;
  // 1. If NewTarget is undefined, let newTarget be the active
  // function object, else let newTarget be NewTarget.
  if (IsUndefined(*args.new_target(), isolate)) {
    new_target = args.target();
  } else {
    new_target = Cast<JSReceiver>(args.new_target());
  }

  // [[Construct]]
  Handle<JSFunction> target = args.target();
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  // 2. Let format be ? OrdinaryCreateFromConstructor(newTarget,
  // "%<T>Prototype%", ...).
  Handle<Map> map;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, map, JSFunction::GetDerivedMap(isolate, target, new_target));

  // 3. Perform ? Initialize<T>(Format, locales, options).
  Handle<T> format;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, format, T::New(isolate, map, locales, options, method_name));
  // 4. Let this be the this value.
  if (IsUndefined(*args.new_target(), isolate)) {
    Handle<JSAny> receiver = args.receiver();
    // 5. If NewTarget is undefined and ? OrdinaryHasInstance(%<T>%, this)
    // is true, then Look up the intrinsic value that has been stored on
    // the context.
    Handle<Object> ordinary_has_instance_obj;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, ordinary_has_instance_obj,
        Object::OrdinaryHasInstance(isolate, constructor, receiver));
    if (Object::BooleanValue(*ordinary_has_instance_obj, isolate)) {
      if (!IsJSReceiver(*receiver)) {
        THROW_NEW_ERROR_RETURN_FAILURE(
            isolate, NewTypeError(MessageTemplate::kIncompatibleMethodReceiver,
                                  isolate->factory()->NewStringFromAsciiChecked(
                                      method_name),
                                  receiver));
      }
      Handle<JSReceiver> rec = Cast<JSReceiver>(receiver);
      // a. Perform ? DefinePropertyOrThrow(this,
      // %Intl%.[[FallbackSymbol]], PropertyDescriptor{ [[Value]]: format,
      // [[Writable]]: false, [[Enumerable]]: false, [[Configurable]]: false }).
      PropertyDescriptor desc;
      desc.set_value(format);
      desc.set_writable(false);
      desc.set_enumerable(false);
      desc.set_configurable(false);
      Maybe<bool> success = JSReceiver::DefineOwnProperty(
          isolate, rec, isolate->factory()->intl_fallback_symbol(), &desc,
          Just(kThrowOnError));
      MAYBE_RETURN(success, ReadOnlyRoots(isolate).exception());
      CHECK(success.FromJust());
      // b. b. Return this.
      return *receiver;
    }
  }
  // 6. Return format.
  return *format;
}

/**
 * Common code shared by ListFormat, RelativeTimeFormat, PluralRules, and
 * Segmenter
 */
template <class T>
Tagged<Object> DisallowCallConstructor(BuiltinArguments args, Isolate* isolate,
                                       v8::Isolate::UseCounterFeature feature,
                                       const char* method_name) {
  isolate->CountUsage(feature);

  // 1. If NewTarget is undefined, throw a TypeError exception.
  if (IsUndefined(*args.new_target(), isolate)) {  // [[Call]]
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kConstructorNotFunction,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  method_name)));
  }
  // [[Construct]]
  Handle<JSFunction> target = args.target();
  Handle<JSReceiver> new_target = Cast<JSReceiver>(args.new_target());

  Handle<Map> map;
  // 2. Let result be OrdinaryCreateFromConstructor(NewTarget,
  //    "%<T>Prototype%").
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, map, JSFunction::GetDerivedMap(isolate, target, new_target));

  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  // 3. Return New<T>(t, locales, options).
  RETURN_RESULT_OR_FAILURE(isolate, T::New(isolate, map, locales, options));
}

/**
 * Common code shared by Collator and V8BreakIterator
 */
template <class T>
Tagged<Object> CallOrConstructConstructor(BuiltinArguments args,
                                          Isolate* isolate,
                                          const char* method_name) {
  Handle<JSReceiver> new_target;

  if (IsUndefined(*args.new_target(), isolate)) {
    new_target = args.target();
  } else {
    new_target = Cast<JSReceiver>(args.new_target());
  }

  // [[Construct]]
  Handle<JSFunction> target = args.target();

  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  Handle<Map> map;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, map, JSFunction::GetDerivedMap(isolate, target, new_target));

  RETURN_RESULT_OR_FAILURE(isolate,
                           T::New(isolate, map, locales, options, method_name));
}

}  // namespace

// Intl.DisplayNames

BUILTIN(DisplayNamesConstructor) {
  HandleScope scope(isolate);

  return DisallowCallConstructor<JSDisplayNames>(
      args, isolate, v8::Isolate::UseCounterFeature::kDisplayNames,
      "Intl.DisplayNames");
}

BUILTIN(DisplayNamesPrototypeResolvedOptions) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDisplayNames, holder,
                 "Intl.DisplayNames.prototype.resolvedOptions");
  return *JSDisplayNames::ResolvedOptions(isolate, holder);
}

BUILTIN(DisplayNamesSupportedLocalesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Intl::SupportedLocalesOf(
                   isolate, "Intl.DisplayNames.supportedLocalesOf",
                   JSDisplayNames::GetAvailableLocales(), locales, options));
}

BUILTIN(DisplayNamesPrototypeOf) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDisplayNames, holder, "Intl.DisplayNames.prototype.of");
  Handle<Object> code_obj = args.atOrUndefined(isolate, 1);

  RETURN_RESULT_OR_FAILURE(isolate,
                           JSDisplayNames::Of(isolate, holder, code_obj));
}

// Intl.DurationFormat
BUILTIN(DurationFormatConstructor) {
  HandleScope scope(isolate);

  return DisallowCallConstructor<JSDurationFormat>(
      args, isolate, v8::Isolate::UseCounterFeature::kDurationFormat,
      "Intl.DurationFormat");
}

BUILTIN(DurationFormatPrototypeResolvedOptions) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDurationFormat, holder,
                 "Intl.DurationFormat.prototype.resolvedOptions");
  return *JSDurationFormat::ResolvedOptions(isolate, holder);
}

BUILTIN(DurationFormatSupportedLocalesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Intl::SupportedLocalesOf(
                   isolate, "Intl.DurationFormat.supportedLocalesOf",
                   JSDurationFormat::GetAvailableLocales(), locales, options));
}

BUILTIN(DurationFormatPrototypeFormat) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDurationFormat, holder,
                 "Intl.DurationFormat.prototype.format");
  Handle<Object> value = args.atOrUndefined(isolate, 1);
  RETURN_RESULT_OR_FAILURE(isolate,
                           JSDurationFormat::Format(isolate, holder, value));
}

BUILTIN(DurationFormatPrototypeFormatToParts) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDurationFormat, holder,
                 "Intl.DurationFormat.prototype.formatToParts");
  Handle<Object> value = args.atOrUndefined(isolate, 1);
  RETURN_RESULT_OR_FAILURE(
      isolate, JSDurationFormat::FormatToParts(isolate, holder, value));
}

// Intl.NumberFormat

BUILTIN(NumberFormatConstructor) {
  HandleScope scope(isolate);

  return LegacyFormatConstructor<JSNumberFormat>(
      args, isolate, v8::Isolate::UseCounterFeature::kNumberFormat,
      isolate->intl_number_format_function(), "Intl.NumberFormat");
}

BUILTIN(NumberFormatPrototypeResolvedOptions) {
  HandleScope scope(isolate);
  const char* const method_name = "Intl.NumberFormat.prototype.resolvedOptions";

  // 1. Let nf be the this value.
  // 2. If Type(nf) is not Object, throw a TypeError exception.
  CHECK_RECEIVER(JSReceiver, number_format_holder, method_name);

  // 3. Let nf be ? UnwrapNumberFormat(nf)
  Handle<JSNumberFormat> number_format;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, number_format,
      JSNumberFormat::UnwrapNumberFormat(isolate, number_format_holder));

  return *JSNumberFormat::ResolvedOptions(isolate, number_format);
}

BUILTIN(NumberFormatPrototypeFormatNumber) {
  const char* const method_name = "get Intl.NumberFormat.prototype.format";
  HandleScope scope(isolate);

  // 1. Let nf be the this value.
  // 2. If Type(nf) is not Object, throw a TypeError exception.
  CHECK_RECEIVER(JSReceiver, receiver, method_name);

  // 3. Let nf be ? UnwrapNumberFormat(nf).
  Handle<JSNumberFormat> number_format;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, number_format,
      JSNumberFormat::UnwrapNumberFormat(isolate, receiver));

  DirectHandle<Object> bound_format(number_format->bound_format(), isolate);

  // 4. If nf.[[BoundFormat]] is undefined, then
  if (!IsUndefined(*bound_format, isolate)) {
    DCHECK(IsJSFunction(*bound_format));
    // 5. Return nf.[[BoundFormat]].
    return *bound_format;
  }

  DirectHandle<JSFunction> new_bound_format_function = CreateBoundFunction(
      isolate, number_format, Builtin::kNumberFormatInternalFormatNumber, 1);

  // 4. c. Set nf.[[BoundFormat]] to F.
  number_format->set_bound_format(*new_bound_format_function);

  // 5. Return nf.[[BoundFormat]].
  return *new_bound_format_function;
}

BUILTIN(NumberFormatInternalFormatNumber) {
  HandleScope scope(isolate);

  DirectHandle<Context> context(isolate->context(), isolate);

  // 1. Let nf be F.[[NumberFormat]].
  // 2. Assert: Type(nf) is Object and nf has an
  //    [[InitializedNumberFormat]] internal slot.
  DirectHandle<JSNumberFormat> number_format(
      Cast<JSNumberFormat>(context->get(
          static_cast<int>(Intl::BoundFunctionContextSlot::kBoundFunction))),
      isolate);

  // 3. If value is not provided, let value be undefined.
  Handle<Object> value = args.atOrUndefined(isolate, 1);

  RETURN_RESULT_OR_FAILURE(isolate, JSNumberFormat::NumberFormatFunction(
                                        isolate, number_format, value));
}

// Common code for NumberFormatPrototypeFormtRange(|ToParts)
template <class T, MaybeHandle<T> (*F)(Isolate*, DirectHandle<JSNumberFormat>,
                                       Handle<Object>, Handle<Object>)>
V8_WARN_UNUSED_RESULT Tagged<Object> NumberFormatRange(
    BuiltinArguments args, Isolate* isolate, const char* const method_name) {
  // 1. Let nf be this value.
  // 2. Perform ? RequireInternalSlot(nf, [[InitializedNumberFormat]]).
  CHECK_RECEIVER(JSNumberFormat, nf, method_name);

  Handle<Object> start = args.atOrUndefined(isolate, 1);
  Handle<Object> end = args.atOrUndefined(isolate, 2);

  Factory* factory = isolate->factory();
  // 3. If start is undefined or end is undefined, throw a TypeError exception.
  if (IsUndefined(*start, isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewTypeError(MessageTemplate::kInvalid,
                     factory->NewStringFromStaticChars("start"), start));
  }
  if (IsUndefined(*end, isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kInvalid,
                              factory->NewStringFromStaticChars("end"), end));
  }

  RETURN_RESULT_OR_FAILURE(isolate, F(isolate, nf, start, end));
}

BUILTIN(NumberFormatPrototypeFormatRange) {
  const char* const method_name = "Intl.NumberFormat.prototype.formatRange";
  HandleScope handle_scope(isolate);
  return NumberFormatRange<String, JSNumberFormat::FormatNumericRange>(
      args, isolate, method_name);
}

BUILTIN(NumberFormatPrototypeFormatRangeToParts) {
  const char* const method_name =
      "Intl.NumberFormat.prototype.formatRangeToParts";
  HandleScope handle_scope(isolate);
  return NumberFormatRange<JSArray, JSNumberFormat::FormatNumericRangeToParts>(
      args, isolate, method_name);
}

BUILTIN(DateTimeFormatConstructor) {
  HandleScope scope(isolate);

  return LegacyFormatConstructor<JSDateTimeFormat>(
      args, isolate, v8::Isolate::UseCounterFeature::kDateTimeFormat,
      isolate->intl_date_time_format_function(), "Intl.DateTimeFormat");
}

BUILTIN(DateTimeFormatPrototypeFormat) {
  const char* const method_name = "get Intl.DateTimeFormat.prototype.format";
  HandleScope scope(isolate);

  // 1. Let dtf be this value.
  // 2. If Type(dtf) is not Object, throw a TypeError exception.
  CHECK_RECEIVER(JSReceiver, receiver, method_name);

  // 3. Let dtf be ? UnwrapDateTimeFormat(dtf).
  Handle<JSDateTimeFormat> format;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, format,
      JSDateTimeFormat::UnwrapDateTimeFormat(isolate, receiver));

  DirectHandle<Object> bound_format =
      DirectHandle<Object>(format->bound_format(), isolate);

  // 4. If dtf.[[BoundFormat]] is undefined, then
  if (!IsUndefined(*bound_format, isolate)) {
    DCHECK(IsJSFunction(*bound_format));
    // 5. Return dtf.[[BoundFormat]].
    return *bound_format;
  }

  DirectHandle<JSFunction> new_bound_format_function = CreateBoundFunction(
      isolate, format, Builtin::kDateTimeFormatInternalFormat, 1);

  // 4.c. Set dtf.[[BoundFormat]] to F.
  format->set_bound_format(*new_bound_format_function);

  // 5. Return dtf.[[BoundFormat]].
  return *new_bound_format_function;
}

BUILTIN(DateTimeFormatInternalFormat) {
  HandleScope scope(isolate);
  DirectHandle<Context> context(isolate->context(), isolate);

  // 1. Let dtf be F.[[DateTimeFormat]].
  // 2. Assert: Type(dtf) is Object and dtf has an [[InitializedDateTimeFormat]]
  // internal slot.
  DirectHandle<JSDateTimeFormat> date_format_holder(
      Cast<JSDateTimeFormat>(context->get(
          static_cast<int>(Intl::BoundFunctionContextSlot::kBoundFunction))),
      isolate);

  Handle<Object> date = args.atOrUndefined(isolate, 1);

  RETURN_RESULT_OR_FAILURE(isolate, JSDateTimeFormat::DateTimeFormat(
                                        isolate, date_format_holder, date,
                                        "DateTime Format Functions"));
}

BUILTIN(IntlGetCanonicalLocales) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);

  RETURN_RESULT_OR_FAILURE(isolate,
                           Intl::GetCanonicalLocales(isolate, locales));
}

BUILTIN(IntlSupportedValuesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);

  RETURN_RESULT_OR_FAILURE(isolate, Intl::SupportedValuesOf(isolate, locales));
}

BUILTIN(ListFormatConstructor) {
  HandleScope scope(isolate);

  return DisallowCallConstructor<JSListFormat>(
      args, isolate, v8::Isolate::UseCounterFeature::kListFormat,
      "Intl.ListFormat");
}

BUILTIN(ListFormatPrototypeResolvedOptions) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSListFormat, format_holder,
                 "Intl.ListFormat.prototype.resolvedOptions");
  return *JSListFormat::ResolvedOptions(isolate
Prompt: 
```
这是目录为v8/src/builtins/builtins-intl.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-intl.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_INTL_SUPPORT
#error Internationalization is expected to be enabled.
#endif  // V8_INTL_SUPPORT

#include <cmath>
#include <list>
#include <memory>

#include "src/builtins/builtins-utils-inl.h"
#include "src/builtins/builtins.h"
#include "src/date/date.h"
#include "src/logging/counters.h"
#include "src/objects/elements.h"
#include "src/objects/intl-objects.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-break-iterator-inl.h"
#include "src/objects/js-collator-inl.h"
#include "src/objects/js-date-time-format-inl.h"
#include "src/objects/js-display-names-inl.h"
#include "src/objects/js-duration-format-inl.h"
#include "src/objects/js-list-format-inl.h"
#include "src/objects/js-locale-inl.h"
#include "src/objects/js-number-format-inl.h"
#include "src/objects/js-plural-rules-inl.h"
#include "src/objects/js-relative-time-format-inl.h"
#include "src/objects/js-segment-iterator-inl.h"
#include "src/objects/js-segmenter-inl.h"
#include "src/objects/js-segments-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/option-utils.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/smi.h"
#include "unicode/brkiter.h"

namespace v8 {
namespace internal {

BUILTIN(StringPrototypeToUpperCaseIntl) {
  HandleScope scope(isolate);
  TO_THIS_STRING(string, "String.prototype.toUpperCase");
  string = String::Flatten(isolate, string);
  RETURN_RESULT_OR_FAILURE(isolate, Intl::ConvertToUpper(isolate, string));
}

BUILTIN(StringPrototypeNormalizeIntl) {
  HandleScope handle_scope(isolate);
  isolate->CountUsage(v8::Isolate::UseCounterFeature::kStringNormalize);
  TO_THIS_STRING(string, "String.prototype.normalize");

  Handle<Object> form_input = args.atOrUndefined(isolate, 1);

  RETURN_RESULT_OR_FAILURE(isolate,
                           Intl::Normalize(isolate, string, form_input));
}

// ecma402 #sup-properties-of-the-string-prototype-object
// ecma402 section 19.1.1.
//   String.prototype.localeCompare ( that [ , locales [ , options ] ] )
// This implementation supersedes the definition provided in ES6.
BUILTIN(StringPrototypeLocaleCompareIntl) {
  HandleScope handle_scope(isolate);

  isolate->CountUsage(v8::Isolate::UseCounterFeature::kStringLocaleCompare);
  static const char* const kMethod = "String.prototype.localeCompare";

  TO_THIS_STRING(str1, kMethod);
  Handle<String> str2;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, str2, Object::ToString(isolate, args.atOrUndefined(isolate, 1)));
  std::optional<int> result = Intl::StringLocaleCompare(
      isolate, str1, str2, args.atOrUndefined(isolate, 2),
      args.atOrUndefined(isolate, 3), kMethod);
  if (!result.has_value()) {
    DCHECK(isolate->has_exception());
    return ReadOnlyRoots(isolate).exception();
  }
  return Smi::FromInt(result.value());
}

BUILTIN(V8BreakIteratorSupportedLocalesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Intl::SupportedLocalesOf(
                   isolate, "Intl.v8BreakIterator.supportedLocalesOf",
                   JSV8BreakIterator::GetAvailableLocales(), locales, options));
}

BUILTIN(NumberFormatSupportedLocalesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Intl::SupportedLocalesOf(
                   isolate, "Intl.NumberFormat.supportedLocalesOf",
                   JSNumberFormat::GetAvailableLocales(), locales, options));
}

BUILTIN(NumberFormatPrototypeFormatToParts) {
  const char* const method_name = "Intl.NumberFormat.prototype.formatToParts";
  HandleScope handle_scope(isolate);
  CHECK_RECEIVER(JSNumberFormat, number_format, method_name);

  Handle<Object> x;
  if (args.length() >= 2) {
    x = args.at(1);
  } else {
    x = isolate->factory()->nan_value();
  }

  RETURN_RESULT_OR_FAILURE(
      isolate, JSNumberFormat::FormatToParts(isolate, number_format, x));
}

BUILTIN(DateTimeFormatPrototypeResolvedOptions) {
  const char* const method_name =
      "Intl.DateTimeFormat.prototype.resolvedOptions";
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSReceiver, format_holder, method_name);

  // 3. Let dtf be ? UnwrapDateTimeFormat(dtf).
  Handle<JSDateTimeFormat> date_time_format;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, date_time_format,
      JSDateTimeFormat::UnwrapDateTimeFormat(isolate, format_holder));

  RETURN_RESULT_OR_FAILURE(
      isolate, JSDateTimeFormat::ResolvedOptions(isolate, date_time_format));
}

BUILTIN(DateTimeFormatSupportedLocalesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Intl::SupportedLocalesOf(
                   isolate, "Intl.DateTimeFormat.supportedLocalesOf",
                   JSDateTimeFormat::GetAvailableLocales(), locales, options));
}

BUILTIN(DateTimeFormatPrototypeFormatToParts) {
  const char* const method_name = "Intl.DateTimeFormat.prototype.formatToParts";
  HandleScope handle_scope(isolate);
  CHECK_RECEIVER(JSObject, date_format_holder, method_name);
  Factory* factory = isolate->factory();

  if (!IsJSDateTimeFormat(*date_format_holder)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kIncompatibleMethodReceiver,
                              factory->NewStringFromAsciiChecked(method_name),
                              date_format_holder));
  }
  auto dtf = Cast<JSDateTimeFormat>(date_format_holder);

  Handle<Object> x = args.atOrUndefined(isolate, 1);
  RETURN_RESULT_OR_FAILURE(isolate, JSDateTimeFormat::FormatToParts(
                                        isolate, dtf, x, false, method_name));
}

// Common code for DateTimeFormatPrototypeFormtRange(|ToParts)
template <class T, MaybeHandle<T> (*F)(Isolate*, Handle<JSDateTimeFormat>,
                                       Handle<Object>, Handle<Object>,
                                       const char* const)>
V8_WARN_UNUSED_RESULT Tagged<Object> DateTimeFormatRange(
    BuiltinArguments args, Isolate* isolate, const char* const method_name) {
  // 1. Let dtf be this value.
  // 2. Perform ? RequireInternalSlot(dtf, [[InitializedDateTimeFormat]]).
  CHECK_RECEIVER(JSDateTimeFormat, dtf, method_name);

  // 3. If startDate is undefined or endDate is undefined, throw a TypeError
  // exception.
  Handle<Object> start_date = args.atOrUndefined(isolate, 1);
  Handle<Object> end_date = args.atOrUndefined(isolate, 2);
  if (IsUndefined(*start_date, isolate) || IsUndefined(*end_date, isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kInvalidTimeValue));
  }

  // 4. Return ? FormatDateTimeRange(dtf, startDate, endDate)
  // OR
  // 4. Return ? FormatDateTimeRangeToParts(dtf, startDate, endDate).
  RETURN_RESULT_OR_FAILURE(isolate,
                           F(isolate, dtf, start_date, end_date, method_name));
}

BUILTIN(DateTimeFormatPrototypeFormatRange) {
  const char* const method_name = "Intl.DateTimeFormat.prototype.formatRange";
  HandleScope handle_scope(isolate);
  return DateTimeFormatRange<String, JSDateTimeFormat::FormatRange>(
      args, isolate, method_name);
}

BUILTIN(DateTimeFormatPrototypeFormatRangeToParts) {
  const char* const method_name =
      "Intl.DateTimeFormat.prototype.formatRangeToParts";
  HandleScope handle_scope(isolate);
  return DateTimeFormatRange<JSArray, JSDateTimeFormat::FormatRangeToParts>(
      args, isolate, method_name);
}

namespace {

Handle<JSFunction> CreateBoundFunction(Isolate* isolate,
                                       DirectHandle<JSObject> object,
                                       Builtin builtin, int len) {
  DirectHandle<NativeContext> native_context(
      isolate->context()->native_context(), isolate);
  Handle<Context> context = isolate->factory()->NewBuiltinContext(
      native_context,
      static_cast<int>(Intl::BoundFunctionContextSlot::kLength));

  context->set(static_cast<int>(Intl::BoundFunctionContextSlot::kBoundFunction),
               *object);

  Handle<SharedFunctionInfo> info =
      isolate->factory()->NewSharedFunctionInfoForBuiltin(
          isolate->factory()->empty_string(), builtin, len, kAdapt);

  return Factory::JSFunctionBuilder{isolate, info, context}
      .set_map(isolate->strict_function_without_prototype_map())
      .Build();
}

/**
 * Common code shared between DateTimeFormatConstructor and
 * NumberFormatConstrutor
 */
template <class T>
Tagged<Object> LegacyFormatConstructor(BuiltinArguments args, Isolate* isolate,
                                       v8::Isolate::UseCounterFeature feature,
                                       Handle<JSAny> constructor,
                                       const char* method_name) {
  isolate->CountUsage(feature);
  Handle<JSReceiver> new_target;
  // 1. If NewTarget is undefined, let newTarget be the active
  // function object, else let newTarget be NewTarget.
  if (IsUndefined(*args.new_target(), isolate)) {
    new_target = args.target();
  } else {
    new_target = Cast<JSReceiver>(args.new_target());
  }

  // [[Construct]]
  Handle<JSFunction> target = args.target();
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  // 2. Let format be ? OrdinaryCreateFromConstructor(newTarget,
  // "%<T>Prototype%", ...).
  Handle<Map> map;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, map, JSFunction::GetDerivedMap(isolate, target, new_target));

  // 3. Perform ? Initialize<T>(Format, locales, options).
  Handle<T> format;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, format, T::New(isolate, map, locales, options, method_name));
  // 4. Let this be the this value.
  if (IsUndefined(*args.new_target(), isolate)) {
    Handle<JSAny> receiver = args.receiver();
    // 5. If NewTarget is undefined and ? OrdinaryHasInstance(%<T>%, this)
    // is true, then Look up the intrinsic value that has been stored on
    // the context.
    Handle<Object> ordinary_has_instance_obj;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, ordinary_has_instance_obj,
        Object::OrdinaryHasInstance(isolate, constructor, receiver));
    if (Object::BooleanValue(*ordinary_has_instance_obj, isolate)) {
      if (!IsJSReceiver(*receiver)) {
        THROW_NEW_ERROR_RETURN_FAILURE(
            isolate, NewTypeError(MessageTemplate::kIncompatibleMethodReceiver,
                                  isolate->factory()->NewStringFromAsciiChecked(
                                      method_name),
                                  receiver));
      }
      Handle<JSReceiver> rec = Cast<JSReceiver>(receiver);
      // a. Perform ? DefinePropertyOrThrow(this,
      // %Intl%.[[FallbackSymbol]], PropertyDescriptor{ [[Value]]: format,
      // [[Writable]]: false, [[Enumerable]]: false, [[Configurable]]: false }).
      PropertyDescriptor desc;
      desc.set_value(format);
      desc.set_writable(false);
      desc.set_enumerable(false);
      desc.set_configurable(false);
      Maybe<bool> success = JSReceiver::DefineOwnProperty(
          isolate, rec, isolate->factory()->intl_fallback_symbol(), &desc,
          Just(kThrowOnError));
      MAYBE_RETURN(success, ReadOnlyRoots(isolate).exception());
      CHECK(success.FromJust());
      // b. b. Return this.
      return *receiver;
    }
  }
  // 6. Return format.
  return *format;
}

/**
 * Common code shared by ListFormat, RelativeTimeFormat, PluralRules, and
 * Segmenter
 */
template <class T>
Tagged<Object> DisallowCallConstructor(BuiltinArguments args, Isolate* isolate,
                                       v8::Isolate::UseCounterFeature feature,
                                       const char* method_name) {
  isolate->CountUsage(feature);

  // 1. If NewTarget is undefined, throw a TypeError exception.
  if (IsUndefined(*args.new_target(), isolate)) {  // [[Call]]
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kConstructorNotFunction,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  method_name)));
  }
  // [[Construct]]
  Handle<JSFunction> target = args.target();
  Handle<JSReceiver> new_target = Cast<JSReceiver>(args.new_target());

  Handle<Map> map;
  // 2. Let result be OrdinaryCreateFromConstructor(NewTarget,
  //    "%<T>Prototype%").
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, map, JSFunction::GetDerivedMap(isolate, target, new_target));

  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  // 3. Return New<T>(t, locales, options).
  RETURN_RESULT_OR_FAILURE(isolate, T::New(isolate, map, locales, options));
}

/**
 * Common code shared by Collator and V8BreakIterator
 */
template <class T>
Tagged<Object> CallOrConstructConstructor(BuiltinArguments args,
                                          Isolate* isolate,
                                          const char* method_name) {
  Handle<JSReceiver> new_target;

  if (IsUndefined(*args.new_target(), isolate)) {
    new_target = args.target();
  } else {
    new_target = Cast<JSReceiver>(args.new_target());
  }

  // [[Construct]]
  Handle<JSFunction> target = args.target();

  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  Handle<Map> map;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, map, JSFunction::GetDerivedMap(isolate, target, new_target));

  RETURN_RESULT_OR_FAILURE(isolate,
                           T::New(isolate, map, locales, options, method_name));
}

}  // namespace

// Intl.DisplayNames

BUILTIN(DisplayNamesConstructor) {
  HandleScope scope(isolate);

  return DisallowCallConstructor<JSDisplayNames>(
      args, isolate, v8::Isolate::UseCounterFeature::kDisplayNames,
      "Intl.DisplayNames");
}

BUILTIN(DisplayNamesPrototypeResolvedOptions) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDisplayNames, holder,
                 "Intl.DisplayNames.prototype.resolvedOptions");
  return *JSDisplayNames::ResolvedOptions(isolate, holder);
}

BUILTIN(DisplayNamesSupportedLocalesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Intl::SupportedLocalesOf(
                   isolate, "Intl.DisplayNames.supportedLocalesOf",
                   JSDisplayNames::GetAvailableLocales(), locales, options));
}

BUILTIN(DisplayNamesPrototypeOf) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDisplayNames, holder, "Intl.DisplayNames.prototype.of");
  Handle<Object> code_obj = args.atOrUndefined(isolate, 1);

  RETURN_RESULT_OR_FAILURE(isolate,
                           JSDisplayNames::Of(isolate, holder, code_obj));
}

// Intl.DurationFormat
BUILTIN(DurationFormatConstructor) {
  HandleScope scope(isolate);

  return DisallowCallConstructor<JSDurationFormat>(
      args, isolate, v8::Isolate::UseCounterFeature::kDurationFormat,
      "Intl.DurationFormat");
}

BUILTIN(DurationFormatPrototypeResolvedOptions) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDurationFormat, holder,
                 "Intl.DurationFormat.prototype.resolvedOptions");
  return *JSDurationFormat::ResolvedOptions(isolate, holder);
}

BUILTIN(DurationFormatSupportedLocalesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Intl::SupportedLocalesOf(
                   isolate, "Intl.DurationFormat.supportedLocalesOf",
                   JSDurationFormat::GetAvailableLocales(), locales, options));
}

BUILTIN(DurationFormatPrototypeFormat) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDurationFormat, holder,
                 "Intl.DurationFormat.prototype.format");
  Handle<Object> value = args.atOrUndefined(isolate, 1);
  RETURN_RESULT_OR_FAILURE(isolate,
                           JSDurationFormat::Format(isolate, holder, value));
}

BUILTIN(DurationFormatPrototypeFormatToParts) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDurationFormat, holder,
                 "Intl.DurationFormat.prototype.formatToParts");
  Handle<Object> value = args.atOrUndefined(isolate, 1);
  RETURN_RESULT_OR_FAILURE(
      isolate, JSDurationFormat::FormatToParts(isolate, holder, value));
}

// Intl.NumberFormat

BUILTIN(NumberFormatConstructor) {
  HandleScope scope(isolate);

  return LegacyFormatConstructor<JSNumberFormat>(
      args, isolate, v8::Isolate::UseCounterFeature::kNumberFormat,
      isolate->intl_number_format_function(), "Intl.NumberFormat");
}

BUILTIN(NumberFormatPrototypeResolvedOptions) {
  HandleScope scope(isolate);
  const char* const method_name = "Intl.NumberFormat.prototype.resolvedOptions";

  // 1. Let nf be the this value.
  // 2. If Type(nf) is not Object, throw a TypeError exception.
  CHECK_RECEIVER(JSReceiver, number_format_holder, method_name);

  // 3. Let nf be ? UnwrapNumberFormat(nf)
  Handle<JSNumberFormat> number_format;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, number_format,
      JSNumberFormat::UnwrapNumberFormat(isolate, number_format_holder));

  return *JSNumberFormat::ResolvedOptions(isolate, number_format);
}

BUILTIN(NumberFormatPrototypeFormatNumber) {
  const char* const method_name = "get Intl.NumberFormat.prototype.format";
  HandleScope scope(isolate);

  // 1. Let nf be the this value.
  // 2. If Type(nf) is not Object, throw a TypeError exception.
  CHECK_RECEIVER(JSReceiver, receiver, method_name);

  // 3. Let nf be ? UnwrapNumberFormat(nf).
  Handle<JSNumberFormat> number_format;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, number_format,
      JSNumberFormat::UnwrapNumberFormat(isolate, receiver));

  DirectHandle<Object> bound_format(number_format->bound_format(), isolate);

  // 4. If nf.[[BoundFormat]] is undefined, then
  if (!IsUndefined(*bound_format, isolate)) {
    DCHECK(IsJSFunction(*bound_format));
    // 5. Return nf.[[BoundFormat]].
    return *bound_format;
  }

  DirectHandle<JSFunction> new_bound_format_function = CreateBoundFunction(
      isolate, number_format, Builtin::kNumberFormatInternalFormatNumber, 1);

  // 4. c. Set nf.[[BoundFormat]] to F.
  number_format->set_bound_format(*new_bound_format_function);

  // 5. Return nf.[[BoundFormat]].
  return *new_bound_format_function;
}

BUILTIN(NumberFormatInternalFormatNumber) {
  HandleScope scope(isolate);

  DirectHandle<Context> context(isolate->context(), isolate);

  // 1. Let nf be F.[[NumberFormat]].
  // 2. Assert: Type(nf) is Object and nf has an
  //    [[InitializedNumberFormat]] internal slot.
  DirectHandle<JSNumberFormat> number_format(
      Cast<JSNumberFormat>(context->get(
          static_cast<int>(Intl::BoundFunctionContextSlot::kBoundFunction))),
      isolate);

  // 3. If value is not provided, let value be undefined.
  Handle<Object> value = args.atOrUndefined(isolate, 1);

  RETURN_RESULT_OR_FAILURE(isolate, JSNumberFormat::NumberFormatFunction(
                                        isolate, number_format, value));
}

// Common code for NumberFormatPrototypeFormtRange(|ToParts)
template <class T, MaybeHandle<T> (*F)(Isolate*, DirectHandle<JSNumberFormat>,
                                       Handle<Object>, Handle<Object>)>
V8_WARN_UNUSED_RESULT Tagged<Object> NumberFormatRange(
    BuiltinArguments args, Isolate* isolate, const char* const method_name) {
  // 1. Let nf be this value.
  // 2. Perform ? RequireInternalSlot(nf, [[InitializedNumberFormat]]).
  CHECK_RECEIVER(JSNumberFormat, nf, method_name);

  Handle<Object> start = args.atOrUndefined(isolate, 1);
  Handle<Object> end = args.atOrUndefined(isolate, 2);

  Factory* factory = isolate->factory();
  // 3. If start is undefined or end is undefined, throw a TypeError exception.
  if (IsUndefined(*start, isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate,
        NewTypeError(MessageTemplate::kInvalid,
                     factory->NewStringFromStaticChars("start"), start));
  }
  if (IsUndefined(*end, isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kInvalid,
                              factory->NewStringFromStaticChars("end"), end));
  }

  RETURN_RESULT_OR_FAILURE(isolate, F(isolate, nf, start, end));
}

BUILTIN(NumberFormatPrototypeFormatRange) {
  const char* const method_name = "Intl.NumberFormat.prototype.formatRange";
  HandleScope handle_scope(isolate);
  return NumberFormatRange<String, JSNumberFormat::FormatNumericRange>(
      args, isolate, method_name);
}

BUILTIN(NumberFormatPrototypeFormatRangeToParts) {
  const char* const method_name =
      "Intl.NumberFormat.prototype.formatRangeToParts";
  HandleScope handle_scope(isolate);
  return NumberFormatRange<JSArray, JSNumberFormat::FormatNumericRangeToParts>(
      args, isolate, method_name);
}

BUILTIN(DateTimeFormatConstructor) {
  HandleScope scope(isolate);

  return LegacyFormatConstructor<JSDateTimeFormat>(
      args, isolate, v8::Isolate::UseCounterFeature::kDateTimeFormat,
      isolate->intl_date_time_format_function(), "Intl.DateTimeFormat");
}

BUILTIN(DateTimeFormatPrototypeFormat) {
  const char* const method_name = "get Intl.DateTimeFormat.prototype.format";
  HandleScope scope(isolate);

  // 1. Let dtf be this value.
  // 2. If Type(dtf) is not Object, throw a TypeError exception.
  CHECK_RECEIVER(JSReceiver, receiver, method_name);

  // 3. Let dtf be ? UnwrapDateTimeFormat(dtf).
  Handle<JSDateTimeFormat> format;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, format,
      JSDateTimeFormat::UnwrapDateTimeFormat(isolate, receiver));

  DirectHandle<Object> bound_format =
      DirectHandle<Object>(format->bound_format(), isolate);

  // 4. If dtf.[[BoundFormat]] is undefined, then
  if (!IsUndefined(*bound_format, isolate)) {
    DCHECK(IsJSFunction(*bound_format));
    // 5. Return dtf.[[BoundFormat]].
    return *bound_format;
  }

  DirectHandle<JSFunction> new_bound_format_function = CreateBoundFunction(
      isolate, format, Builtin::kDateTimeFormatInternalFormat, 1);

  // 4.c. Set dtf.[[BoundFormat]] to F.
  format->set_bound_format(*new_bound_format_function);

  // 5. Return dtf.[[BoundFormat]].
  return *new_bound_format_function;
}

BUILTIN(DateTimeFormatInternalFormat) {
  HandleScope scope(isolate);
  DirectHandle<Context> context(isolate->context(), isolate);

  // 1. Let dtf be F.[[DateTimeFormat]].
  // 2. Assert: Type(dtf) is Object and dtf has an [[InitializedDateTimeFormat]]
  // internal slot.
  DirectHandle<JSDateTimeFormat> date_format_holder(
      Cast<JSDateTimeFormat>(context->get(
          static_cast<int>(Intl::BoundFunctionContextSlot::kBoundFunction))),
      isolate);

  Handle<Object> date = args.atOrUndefined(isolate, 1);

  RETURN_RESULT_OR_FAILURE(isolate, JSDateTimeFormat::DateTimeFormat(
                                        isolate, date_format_holder, date,
                                        "DateTime Format Functions"));
}

BUILTIN(IntlGetCanonicalLocales) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);

  RETURN_RESULT_OR_FAILURE(isolate,
                           Intl::GetCanonicalLocales(isolate, locales));
}

BUILTIN(IntlSupportedValuesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);

  RETURN_RESULT_OR_FAILURE(isolate, Intl::SupportedValuesOf(isolate, locales));
}

BUILTIN(ListFormatConstructor) {
  HandleScope scope(isolate);

  return DisallowCallConstructor<JSListFormat>(
      args, isolate, v8::Isolate::UseCounterFeature::kListFormat,
      "Intl.ListFormat");
}

BUILTIN(ListFormatPrototypeResolvedOptions) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSListFormat, format_holder,
                 "Intl.ListFormat.prototype.resolvedOptions");
  return *JSListFormat::ResolvedOptions(isolate, format_holder);
}

BUILTIN(ListFormatSupportedLocalesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Intl::SupportedLocalesOf(
                   isolate, "Intl.ListFormat.supportedLocalesOf",
                   JSListFormat::GetAvailableLocales(), locales, options));
}

// Intl.Locale implementation
BUILTIN(LocaleConstructor) {
  HandleScope scope(isolate);

  isolate->CountUsage(v8::Isolate::UseCounterFeature::kLocale);

  const char* method_name = "Intl.Locale";
  if (IsUndefined(*args.new_target(), isolate)) {  // [[Call]]
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kConstructorNotFunction,
                              isolate->factory()->NewStringFromAsciiChecked(
                                  method_name)));
  }
  // [[Construct]]
  Handle<JSFunction> target = args.target();
  Handle<JSReceiver> new_target = Cast<JSReceiver>(args.new_target());

  Handle<Object> tag = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  Handle<Map> map;
  // 6. Let locale be ? OrdinaryCreateFromConstructor(NewTarget,
  // %LocalePrototype%, internalSlotsList).
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, map, JSFunction::GetDerivedMap(isolate, target, new_target));

  // 7. If Type(tag) is not String or Object, throw a TypeError exception.
  if (!IsString(*tag) && !IsJSReceiver(*tag)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kLocaleNotEmpty));
  }

  Handle<String> locale_string;
  // 8. If Type(tag) is Object and tag has an [[InitializedLocale]] internal
  // slot, then
  if (IsJSLocale(*tag)) {
    // a. Let tag be tag.[[Locale]].
    locale_string = JSLocale::ToString(isolate, Cast<JSLocale>(tag));
  } else {  // 9. Else,
    // a. Let tag be ? ToString(tag).
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, locale_string,
                                       Object::ToString(isolate, tag));
  }

  // 10. Set options to ? CoerceOptionsToObject(options).
  Handle<JSReceiver> options_object;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, options_object,
      CoerceOptionsToObject(isolate, options, method_name));

  RETURN_RESULT_OR_FAILURE(
      isolate, JSLocale::New(isolate, map, locale_string, options_object));
}

BUILTIN(LocalePrototypeMaximize) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.maximize");
  RETURN_RESULT_OR_FAILURE(isolate, JSLocale::Maximize(isolate, locale));
}

BUILTIN(LocalePrototypeMinimize) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.minimize");
  RETURN_RESULT_OR_FAILURE(isolate, JSLocale::Minimize(isolate, locale));
}

BUILTIN(LocalePrototypeGetCalendars) {
  HandleScope scope(isolate);
  isolate->CountUsage(v8::Isolate::UseCounterFeature::kLocaleInfoFunctions);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.getCalendars");
  RETURN_RESULT_OR_FAILURE(isolate, JSLocale::GetCalendars(isolate, locale));
}

BUILTIN(LocalePrototypeGetCollations) {
  HandleScope scope(isolate);
  isolate->CountUsage(v8::Isolate::UseCounterFeature::kLocaleInfoFunctions);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.getCollations");
  RETURN_RESULT_OR_FAILURE(isolate, JSLocale::GetCollations(isolate, locale));
}

BUILTIN(LocalePrototypeGetHourCycles) {
  HandleScope scope(isolate);
  isolate->CountUsage(v8::Isolate::UseCounterFeature::kLocaleInfoFunctions);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.getHourCycles");
  RETURN_RESULT_OR_FAILURE(isolate, JSLocale::GetHourCycles(isolate, locale));
}

BUILTIN(LocalePrototypeGetNumberingSystems) {
  HandleScope scope(isolate);
  isolate->CountUsage(v8::Isolate::UseCounterFeature::kLocaleInfoFunctions);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.getNumberingSystems");
  RETURN_RESULT_OR_FAILURE(isolate,
                           JSLocale::GetNumberingSystems(isolate, locale));
}

BUILTIN(LocalePrototypeGetTextInfo) {
  HandleScope scope(isolate);
  isolate->CountUsage(v8::Isolate::UseCounterFeature::kLocaleInfoFunctions);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.getTextInfo");
  RETURN_RESULT_OR_FAILURE(isolate, JSLocale::GetTextInfo(isolate, locale));
}

BUILTIN(LocalePrototypeGetTimeZones) {
  HandleScope scope(isolate);
  isolate->CountUsage(v8::Isolate::UseCounterFeature::kLocaleInfoFunctions);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.getTimeZones");
  RETURN_RESULT_OR_FAILURE(isolate, JSLocale::GetTimeZones(isolate, locale));
}

BUILTIN(LocalePrototypeGetWeekInfo) {
  HandleScope scope(isolate);
  isolate->CountUsage(v8::Isolate::UseCounterFeature::kLocaleInfoFunctions);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.getWeekInfo");
  RETURN_RESULT_OR_FAILURE(isolate, JSLocale::GetWeekInfo(isolate, locale));
}

BUILTIN(LocalePrototypeCalendars) {
  HandleScope scope(isolate);
  isolate->CountUsage(
      v8::Isolate::UseCounterFeature::kLocaleInfoObsoletedGetters);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.calendars");
  RETURN_RESULT_OR_FAILURE(isolate, JSLocale::GetCalendars(isolate, locale));
}

BUILTIN(LocalePrototypeCollations) {
  HandleScope scope(isolate);
  isolate->CountUsage(
      v8::Isolate::UseCounterFeature::kLocaleInfoObsoletedGetters);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.collations");
  RETURN_RESULT_OR_FAILURE(isolate, JSLocale::GetCollations(isolate, locale));
}

BUILTIN(LocalePrototypeHourCycles) {
  HandleScope scope(isolate);
  isolate->CountUsage(
      v8::Isolate::UseCounterFeature::kLocaleInfoObsoletedGetters);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.hourCycles");
  RETURN_RESULT_OR_FAILURE(isolate, JSLocale::GetHourCycles(isolate, locale));
}

BUILTIN(LocalePrototypeNumberingSystems) {
  HandleScope scope(isolate);
  isolate->CountUsage(
      v8::Isolate::UseCounterFeature::kLocaleInfoObsoletedGetters);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.numberingSystems");
  RETURN_RESULT_OR_FAILURE(isolate,
                           JSLocale::GetNumberingSystems(isolate, locale));
}

BUILTIN(LocalePrototypeTextInfo) {
  HandleScope scope(isolate);
  isolate->CountUsage(
      v8::Isolate::UseCounterFeature::kLocaleInfoObsoletedGetters);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.textInfo");
  RETURN_RESULT_OR_FAILURE(isolate, JSLocale::GetTextInfo(isolate, locale));
}

BUILTIN(LocalePrototypeTimeZones) {
  HandleScope scope(isolate);
  isolate->CountUsage(
      v8::Isolate::UseCounterFeature::kLocaleInfoObsoletedGetters);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.timeZones");
  RETURN_RESULT_OR_FAILURE(isolate, JSLocale::GetTimeZones(isolate, locale));
}

BUILTIN(LocalePrototypeWeekInfo) {
  HandleScope scope(isolate);
  isolate->CountUsage(
      v8::Isolate::UseCounterFeature::kLocaleInfoObsoletedGetters);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.weekInfo");
  RETURN_RESULT_OR_FAILURE(isolate, JSLocale::GetWeekInfo(isolate, locale));
}

BUILTIN(RelativeTimeFormatSupportedLocalesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  RETURN_RESULT_OR_FAILURE(
      isolate,
      Intl::SupportedLocalesOf(
          isolate, "Intl.RelativeTimeFormat.supportedLocalesOf",
          JSRelativeTimeFormat::GetAvailableLocales(), locales, options));
}

BUILTIN(RelativeTimeFormatPrototypeFormat) {
  HandleScope scope(isolate);
  // 1. Let relativeTimeFormat be the this value.
  // 2. If Type(relativeTimeFormat) is not Object or relativeTimeFormat does not
  //    have an [[InitializedRelativeTimeFormat]] internal slot whose value is
  //    true, throw a TypeError exception.
  CHECK_RECEIVER(JSRelativeTimeFormat, format_holder,
                 "Intl.RelativeTimeFormat.prototype.format");
  Handle<Object> value_obj = args.atOrUndefined(isolate, 1);
  Handle<Object> unit_obj = args.atOrUndefined(isolate, 2);

  RETURN_RESULT_OR_FAILURE(
      isolate, JSRelativeTimeFormat::Format(isolate, value_obj, unit_obj,
"""


```