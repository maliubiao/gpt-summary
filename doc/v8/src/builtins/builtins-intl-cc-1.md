Response:
The user wants a summary of the provided C++ code snippet for `v8/src/builtins/builtins-intl.cc`.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The filename "builtins-intl.cc" strongly suggests this code implements the ECMAScript Internationalization API (Intl).

2. **Analyze the `BUILTIN` Macros:** These macros define the entry points for JavaScript calls into the C++ implementation. Look for patterns like `Constructor`, `Prototype`, `ResolvedOptions`, `SupportedLocalesOf`, and methods like `format`, `compare`, `segment`, etc.

3. **Group by Intl Object:**  The code is organized around specific Intl objects like `DateTimeFormat`, `NumberFormat`, `RelativeTimeFormat`, `Locale`, `PluralRules`, `Collator`, `Segmenter`, and `v8BreakIterator`. Summarize the functionality for each of these.

4. **Look for Common Operations:**  Notice the recurring patterns of:
    * **Constructor:** Creating new instances of Intl objects.
    * **ResolvedOptions:** Getting the final, computed options.
    * **SupportedLocalesOf:** Determining which locales are supported.
    * **`format` methods:** Formatting dates, numbers, or relative times.
    * **`compare` methods:** Comparing strings according to locale-specific rules.
    * **`select` methods:** Selecting plural forms.
    * **`segment` methods:** Segmenting text.
    * **Locale getters:** Accessing properties of `Intl.Locale` objects.

5. **Check for `.tq` Mentions:** The prompt asks about `.tq` files (Torque). This file does *not* end in `.tq`, so it's standard C++.

6. **JavaScript Examples:** For each major Intl object, provide a concise JavaScript example illustrating its usage.

7. **Code Logic and Examples:**  For methods with more complex logic (like `PluralRules.prototype.selectRange`), provide hypothetical inputs and outputs to demonstrate the behavior.

8. **Common Programming Errors:** Think about typical mistakes developers might make when using these Intl APIs. Examples include passing incorrect arguments or using the API on non-object types.

9. **Synthesize the Summary:** Combine the information gathered in the previous steps into a concise summary of the file's overall functionality.

**Self-Correction/Refinement:**

* Initially, I might focus too much on individual `BUILTIN` functions. It's important to group them by the Intl object they belong to for a more coherent summary.
*  Ensure the JavaScript examples are clear and directly relate to the C++ code's functionality.
*  When describing code logic, avoid getting too deep into the C++ implementation details and focus on the observable behavior from a JavaScript perspective.
*  Double-check that the examples of common errors are realistic and helpful.

By following this structured approach, I can generate a comprehensive and accurate summary of the provided C++ code for the Intl built-ins.
Based on the provided C++ source code for `v8/src/builtins/builtins-intl.cc`, here's a summary of its functionality:

**Core Functionality:**

This file implements the built-in functions for the ECMAScript Internationalization API (Intl) in V8. It provides the core logic for various internationalization features, allowing JavaScript developers to work with culturally sensitive data like dates, times, numbers, currencies, and text segments.

**Key Areas Covered:**

* **`Intl.DateTimeFormat`:**  Handles formatting and parsing of dates and times according to specified locales and options.
    * Provides constructors, `resolvedOptions`, `format`, and `formatToParts` methods.
* **`Intl.NumberFormat`:**  Handles formatting of numbers, including currencies and percentages, according to locales and options.
    * Offers constructors, `resolvedOptions`, `format`, and `formatToParts` methods.
* **`Intl.RelativeTimeFormat`:**  Formats relative times (e.g., "in 5 days", "2 months ago").
    * Includes constructors, `resolvedOptions`, `format`, and `formatToParts` methods.
* **`Intl.Locale`:** Represents a specific locale and provides access to its properties.
    * Implements getter methods for various locale components like `language`, `script`, `region`, `baseName`, `calendar`, `caseFirst`, `collation`, `firstDayOfWeek`, `hourCycle`, `numeric`, and `numberingSystem`. It also has a `toString` method.
* **`Intl.PluralRules`:**  Determines the plural form of a number based on the rules of a given locale.
    * Includes constructors, `resolvedOptions`, `select` (for a single number), and `selectRange` (for a range of numbers).
* **`Intl.Collator`:**  Provides locale-sensitive string comparison.
    * Offers constructors, `resolvedOptions`, `compare` (which returns a bound function for comparison), and an internal `CollatorInternalCompare` function.
* **`Intl.Segmenter`:**  Allows for the segmentation of text into meaningful units (words, sentences, graphemes).
    * Implements constructors, `supportedLocalesOf`, `resolvedOptions`, and `segment` (which returns a `Segments` object).
* **`Intl.v8BreakIterator`:**  A V8-specific break iterator that provides similar functionality to `Intl.Segmenter` for text segmentation.
    * Includes constructors, `resolvedOptions`, and methods like `adoptText`, `first`, `next`, `current`, and `breakType`.

**Regarding the filename and Torque:**

The file `v8/src/builtins/builtins-intl.cc` ends with `.cc`, which signifies it's a standard C++ source file. Therefore, it's **not** a v8 Torque source file. If it were a Torque file, it would end with `.tq`.

**Relationship to JavaScript and Examples:**

The functions defined in this C++ file are directly accessible and used by JavaScript through the `Intl` object. Here are some JavaScript examples demonstrating the functionality:

**`Intl.DateTimeFormat`:**

```javascript
const date = new Date();
const formatter = new Intl.DateTimeFormat('en-US', { dateStyle: 'full' });
console.log(formatter.format(date)); // Output: e.g., "Wednesday, July 26, 2023"
```

**`Intl.NumberFormat`:**

```javascript
const number = 12345.67;
const formatter = new Intl.NumberFormat('de-DE', { style: 'currency', currency: 'EUR' });
console.log(formatter.format(number)); // Output: "12.345,67 €"
```

**`Intl.RelativeTimeFormat`:**

```javascript
const rtf = new Intl.RelativeTimeFormat('es', { numeric: 'auto' });
console.log(rtf.format(-1, 'day'));   // Output: "ayer"
console.log(rtf.format(5, 'month'));  // Output: "dentro de 5 meses"
```

**`Intl.Locale`:**

```javascript
const locale = new Intl.Locale('en-US-u-ca-gregory-nu-arab');
console.log(locale.language);    // Output: "en"
console.log(locale.region);      // Output: "US"
console.log(locale.calendar);    // Output: "gregory"
console.log(locale.numberingSystem); // Output: "arab"
```

**`Intl.PluralRules`:**

```javascript
const pr = new Intl.PluralRules('en-US');
console.log(pr.select(0));    // Output: "other"
console.log(pr.select(1));    // Output: "one"
console.log(pr.select(2));    // Output: "other"

const prRange = new Intl.PluralRules('fr-FR');
console.log(prRange.selectRange(1, 5)); // Output: "other"
```

**`Intl.Collator`:**

```javascript
const collator = new Intl.Collator('de');
const strings = ['ä', 'z', 'a'];
strings.sort(collator.compare);
console.log(strings); // Output: ["a", "ä", "z"]
```

**`Intl.Segmenter`:**

```javascript
const segmenter = new Intl.Segmenter('en', { granularity: 'word' });
const text = "This is a sentence.";
const segments = segmenter.segment(text);
for (const segment of segments) {
  console.log(segment.segment);
}
```

**Code Logic Inference and Examples:**

**`PluralRulesPrototypeSelectRange`:**

* **Assumption:** The `PluralRules` object is initialized for a specific locale (e.g., 'en-US').
* **Input:** `start = 1`, `end = 5`
* **Output:** The plural category that best represents the range from 1 to 5 (inclusive) according to the locale's pluralization rules. For 'en-US', this would likely be "other".
* **Input:** `start = 1`, `end = 1`
* **Output:** The plural category for the number 1, which is "one" for 'en-US'.

**Common Programming Errors:**

* **Incorrect `this` value:** Calling a prototype method like `format` or `resolvedOptions` on a non-`Intl` object will result in a `TypeError`.

```javascript
const format = Intl.NumberFormat.prototype.format;
try {
  format(123); // TypeError: ... is not an object
} catch (e) {
  console.error(e);
}

const nf = new Intl.NumberFormat('en-US');
try {
  nf.resolvedOptions.call(null); // TypeError: ... is not an object
} catch (e) {
  console.error(e);
}
```

* **Passing incorrect argument types:**  Providing arguments of the wrong type (e.g., a string where a number is expected) can lead to errors.

```javascript
const pr = new Intl.PluralRules('en-US');
try {
  pr.select("hello"); // Error (likely a TypeError or NaN conversion issue internally)
} catch (e) {
  console.error(e);
}
```

* **Using uninitialized `Intl` objects:**  Trying to use methods on an `Intl` object before it's properly constructed.

```javascript
let nf;
// ... some conditional logic that might not initialize nf ...
try {
  nf.format(10); // TypeError: Cannot read properties of undefined (reading 'format')
} catch (e) {
  console.error(e);
}
```

**归纳一下它的功能 (Summary of its Functionality):**

This C++ file serves as the core implementation within V8 for the ECMAScript Internationalization API (Intl). It provides the underlying logic and functionality for formatting and manipulating culturally sensitive data like dates, times, numbers, currencies, relative times, and text segments. It also handles locale-aware string comparison and provides access to locale properties. Essentially, it bridges the gap between JavaScript's `Intl` object and the platform's internationalization capabilities, often relying on libraries like ICU (International Components for Unicode).

Prompt: 
```
这是目录为v8/src/builtins/builtins-intl.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-intl.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""

                                            format_holder));
}

BUILTIN(RelativeTimeFormatPrototypeFormatToParts) {
  HandleScope scope(isolate);
  // 1. Let relativeTimeFormat be the this value.
  // 2. If Type(relativeTimeFormat) is not Object or relativeTimeFormat does not
  //    have an [[InitializedRelativeTimeFormat]] internal slot whose value is
  //    true, throw a TypeError exception.
  CHECK_RECEIVER(JSRelativeTimeFormat, format_holder,
                 "Intl.RelativeTimeFormat.prototype.formatToParts");
  Handle<Object> value_obj = args.atOrUndefined(isolate, 1);
  Handle<Object> unit_obj = args.atOrUndefined(isolate, 2);
  RETURN_RESULT_OR_FAILURE(
      isolate, JSRelativeTimeFormat::FormatToParts(isolate, value_obj, unit_obj,
                                                   format_holder));
}

// Locale getters.
BUILTIN(LocalePrototypeLanguage) {
  HandleScope scope(isolate);
  // CHECK_RECEIVER will case locale_holder to JSLocale.
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.language");

  return *JSLocale::Language(isolate, locale);
}

BUILTIN(LocalePrototypeScript) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.script");

  return *JSLocale::Script(isolate, locale);
}

BUILTIN(LocalePrototypeRegion) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.region");

  return *JSLocale::Region(isolate, locale);
}

BUILTIN(LocalePrototypeBaseName) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.baseName");

  return *JSLocale::BaseName(isolate, locale);
}

BUILTIN(LocalePrototypeCalendar) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.calendar");

  return *JSLocale::Calendar(isolate, locale);
}

BUILTIN(LocalePrototypeCaseFirst) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.caseFirst");

  return *JSLocale::CaseFirst(isolate, locale);
}

BUILTIN(LocalePrototypeCollation) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.collation");

  return *JSLocale::Collation(isolate, locale);
}

BUILTIN(LocalePrototypeFirstDayOfWeek) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.firstDayOfWeek");

  return *JSLocale::FirstDayOfWeek(isolate, locale);
}

BUILTIN(LocalePrototypeHourCycle) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.hourCycle");

  return *JSLocale::HourCycle(isolate, locale);
}

BUILTIN(LocalePrototypeNumeric) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.numeric");

  return *JSLocale::Numeric(isolate, locale);
}

BUILTIN(LocalePrototypeNumberingSystem) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.numberingSystem");

  return *JSLocale::NumberingSystem(isolate, locale);
}

BUILTIN(LocalePrototypeToString) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSLocale, locale, "Intl.Locale.prototype.toString");

  return *JSLocale::ToString(isolate, locale);
}

BUILTIN(RelativeTimeFormatConstructor) {
  HandleScope scope(isolate);

  return DisallowCallConstructor<JSRelativeTimeFormat>(
      args, isolate, v8::Isolate::UseCounterFeature::kRelativeTimeFormat,
      "Intl.RelativeTimeFormat");
}

BUILTIN(RelativeTimeFormatPrototypeResolvedOptions) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSRelativeTimeFormat, format_holder,
                 "Intl.RelativeTimeFormat.prototype.resolvedOptions");
  return *JSRelativeTimeFormat::ResolvedOptions(isolate, format_holder);
}

bool IsFastLocale(Tagged<Object> maybe_locale) {
  DisallowGarbageCollection no_gc;
  if (!IsSeqOneByteString(maybe_locale)) {
    return false;
  }
  auto locale = Cast<SeqOneByteString>(maybe_locale);
  uint8_t* chars = locale->GetChars(no_gc);
  if (locale->length() < 2 || !std::isalpha(chars[0]) ||
      !std::isalpha(chars[1])) {
    return false;
  }
  if (locale->length() != 2 &&
      (locale->length() != 5 || chars[2] != '-' || !std::isalpha(chars[3]) ||
       !std::isalpha(chars[4]))) {
    return false;
  }
  char first = chars[0] | 0x20;
  char second = chars[1] | 0x20;
  return (first != 'a' || second != 'z') && (first != 'e' || second != 'l') &&
         (first != 'l' || second != 't') && (first != 't' || second != 'r');
}

BUILTIN(StringPrototypeToLocaleUpperCase) {
  HandleScope scope(isolate);
  Handle<Object> maybe_locale = args.atOrUndefined(isolate, 1);
  TO_THIS_STRING(string, "String.prototype.toLocaleUpperCase");
  if (IsUndefined(*maybe_locale) || IsFastLocale(*maybe_locale)) {
    string = String::Flatten(isolate, string);
    RETURN_RESULT_OR_FAILURE(isolate, Intl::ConvertToUpper(isolate, string));
  } else {
    RETURN_RESULT_OR_FAILURE(isolate, Intl::StringLocaleConvertCase(
                                          isolate, string, true, maybe_locale));
  }
}

BUILTIN(PluralRulesConstructor) {
  HandleScope scope(isolate);

  return DisallowCallConstructor<JSPluralRules>(
      args, isolate, v8::Isolate::UseCounterFeature::kPluralRules,
      "Intl.PluralRules");
}

BUILTIN(PluralRulesPrototypeResolvedOptions) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSPluralRules, plural_rules_holder,
                 "Intl.PluralRules.prototype.resolvedOptions");
  return *JSPluralRules::ResolvedOptions(isolate, plural_rules_holder);
}

BUILTIN(PluralRulesPrototypeSelect) {
  HandleScope scope(isolate);

  // 1. 1. Let pr be the this value.
  // 2. Perform ? RequireInternalSlot(pr, [[InitializedPluralRules]]).
  CHECK_RECEIVER(JSPluralRules, plural_rules,
                 "Intl.PluralRules.prototype.select");

  // 3. Let n be ? ToNumber(value).
  Handle<Object> number = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, number,
                                     Object::ToNumber(isolate, number));
  double number_double = Object::NumberValue(*number);

  // 4. Return ! ResolvePlural(pr, n).
  RETURN_RESULT_OR_FAILURE(isolate, JSPluralRules::ResolvePlural(
                                        isolate, plural_rules, number_double));
}

BUILTIN(PluralRulesPrototypeSelectRange) {
  HandleScope scope(isolate);

  // 1. Let pr be the this value.
  // 2. Perform ? RequireInternalSlot(pr, [[InitializedPluralRules]]).
  CHECK_RECEIVER(JSPluralRules, plural_rules,
                 "Intl.PluralRules.prototype.selectRange");

  // 3. If start is undefined or end is undefined, throw a TypeError exception.
  Handle<Object> start = args.atOrUndefined(isolate, 1);
  Handle<Object> end = args.atOrUndefined(isolate, 2);
  if (IsUndefined(*start)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kInvalid,
                              isolate->factory()->startRange_string(), start));
  }
  if (IsUndefined(*end)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kInvalid,
                              isolate->factory()->endRange_string(), end));
  }

  // 4. Let x be ? ToNumber(start).
  Handle<Object> x;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, x,
                                     Object::ToNumber(isolate, start));

  // 5. Let y be ? ToNumber(end).
  Handle<Object> y;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, y,
                                     Object::ToNumber(isolate, end));

  // 6. Return ! ResolvePluralRange(pr, x, y).
  if (IsNaN(*x)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewRangeError(MessageTemplate::kInvalid,
                               isolate->factory()->startRange_string(), x));
  }
  if (IsNaN(*y)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewRangeError(MessageTemplate::kInvalid,
                               isolate->factory()->endRange_string(), y));
  }

  RETURN_RESULT_OR_FAILURE(
      isolate, JSPluralRules::ResolvePluralRange(isolate, plural_rules,
                                                 Object::NumberValue(*x),
                                                 Object::NumberValue(*y)));
}

BUILTIN(PluralRulesSupportedLocalesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Intl::SupportedLocalesOf(
                   isolate, "Intl.PluralRules.supportedLocalesOf",
                   JSPluralRules::GetAvailableLocales(), locales, options));
}

BUILTIN(CollatorConstructor) {
  HandleScope scope(isolate);

  isolate->CountUsage(v8::Isolate::UseCounterFeature::kCollator);

  return CallOrConstructConstructor<JSCollator>(args, isolate, "Intl.Collator");
}

BUILTIN(CollatorPrototypeResolvedOptions) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSCollator, collator_holder,
                 "Intl.Collator.prototype.resolvedOptions");
  return *JSCollator::ResolvedOptions(isolate, collator_holder);
}

BUILTIN(CollatorSupportedLocalesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Intl::SupportedLocalesOf(
                   isolate, "Intl.Collator.supportedLocalesOf",
                   JSCollator::GetAvailableLocales(), locales, options));
}

BUILTIN(CollatorPrototypeCompare) {
  const char* const method_name = "get Intl.Collator.prototype.compare";
  HandleScope scope(isolate);

  // 1. Let collator be this value.
  // 2. If Type(collator) is not Object, throw a TypeError exception.
  // 3. If collator does not have an [[InitializedCollator]] internal slot,
  // throw a TypeError exception.
  CHECK_RECEIVER(JSCollator, collator, method_name);

  // 4. If collator.[[BoundCompare]] is undefined, then
  DirectHandle<Object> bound_compare(collator->bound_compare(), isolate);
  if (!IsUndefined(*bound_compare, isolate)) {
    DCHECK(IsJSFunction(*bound_compare));
    // 5. Return collator.[[BoundCompare]].
    return *bound_compare;
  }

  DirectHandle<JSFunction> new_bound_compare_function = CreateBoundFunction(
      isolate, collator, Builtin::kCollatorInternalCompare, 2);

  // 4.c. Set collator.[[BoundCompare]] to F.
  collator->set_bound_compare(*new_bound_compare_function);

  // 5. Return collator.[[BoundCompare]].
  return *new_bound_compare_function;
}

BUILTIN(CollatorInternalCompare) {
  HandleScope scope(isolate);
  DirectHandle<Context> context(isolate->context(), isolate);

  // 1. Let collator be F.[[Collator]].
  // 2. Assert: Type(collator) is Object and collator has an
  // [[InitializedCollator]] internal slot.
  DirectHandle<JSCollator> collator(
      Cast<JSCollator>(context->get(
          static_cast<int>(Intl::BoundFunctionContextSlot::kBoundFunction))),
      isolate);

  // 3. If x is not provided, let x be undefined.
  Handle<Object> x = args.atOrUndefined(isolate, 1);
  // 4. If y is not provided, let y be undefined.
  Handle<Object> y = args.atOrUndefined(isolate, 2);

  // 5. Let X be ? ToString(x).
  Handle<String> string_x;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, string_x,
                                     Object::ToString(isolate, x));
  // 6. Let Y be ? ToString(y).
  Handle<String> string_y;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, string_y,
                                     Object::ToString(isolate, y));

  // 7. Return CompareStrings(collator, X, Y).
  icu::Collator* icu_collator = collator->icu_collator()->raw();
  CHECK_NOT_NULL(icu_collator);
  return Smi::FromInt(
      Intl::CompareStrings(isolate, *icu_collator, string_x, string_y));
}

// ecma402 #sec-%segmentiteratorprototype%.next
BUILTIN(SegmentIteratorPrototypeNext) {
  const char* const method_name = "%SegmentIterator.prototype%.next";
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSSegmentIterator, segment_iterator, method_name);

  RETURN_RESULT_OR_FAILURE(isolate,
                           JSSegmentIterator::Next(isolate, segment_iterator));
}

// ecma402 #sec-intl.segmenter
BUILTIN(SegmenterConstructor) {
  HandleScope scope(isolate);

  return DisallowCallConstructor<JSSegmenter>(
      args, isolate, v8::Isolate::UseCounterFeature::kSegmenter,
      "Intl.Segmenter");
}

// ecma402 #sec-intl.segmenter.supportedlocalesof
BUILTIN(SegmenterSupportedLocalesOf) {
  HandleScope scope(isolate);
  Handle<Object> locales = args.atOrUndefined(isolate, 1);
  Handle<Object> options = args.atOrUndefined(isolate, 2);

  RETURN_RESULT_OR_FAILURE(
      isolate, Intl::SupportedLocalesOf(
                   isolate, "Intl.Segmenter.supportedLocalesOf",
                   JSSegmenter::GetAvailableLocales(), locales, options));
}

// ecma402 #sec-intl.segmenter.prototype.resolvedoptions
BUILTIN(SegmenterPrototypeResolvedOptions) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSSegmenter, segmenter,
                 "Intl.Segmenter.prototype.resolvedOptions");
  return *JSSegmenter::ResolvedOptions(isolate, segmenter);
}

// ecma402 #sec-intl.segmenter.prototype.segment
BUILTIN(SegmenterPrototypeSegment) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSSegmenter, segmenter, "Intl.Segmenter.prototype.segment");
  Handle<Object> input_text = args.atOrUndefined(isolate, 1);
  // 3. Let string be ? ToString(string).
  Handle<String> string;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, string,
                                     Object::ToString(isolate, input_text));

  // 4. Return ? CreateSegmentsObject(segmenter, string).
  RETURN_RESULT_OR_FAILURE(isolate,
                           JSSegments::Create(isolate, segmenter, string));
}

// ecma402 #sec-%segmentsprototype%.containing
BUILTIN(SegmentsPrototypeContaining) {
  const char* const method_name = "%Segments.prototype%.containing";
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSSegments, segments, method_name);
  Handle<Object> index = args.atOrUndefined(isolate, 1);

  // 6. Let n be ? ToInteger(index).
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, index,
                                     Object::ToInteger(isolate, index));
  double const n = Object::NumberValue(*index);

  RETURN_RESULT_OR_FAILURE(isolate,
                           JSSegments::Containing(isolate, segments, n));
}

// ecma402 #sec-%segmentsprototype%-@@iterator
BUILTIN(SegmentsPrototypeIterator) {
  const char* const method_name = "%SegmentIsPrototype%[@@iterator]";
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSSegments, segments, method_name);
  RETURN_RESULT_OR_FAILURE(
      isolate,
      JSSegmentIterator::Create(
          isolate, handle(segments->raw_string(), isolate),
          segments->icu_break_iterator()->raw(), segments->granularity()));
}

BUILTIN(V8BreakIteratorConstructor) {
  HandleScope scope(isolate);

  return CallOrConstructConstructor<JSV8BreakIterator>(args, isolate,
                                                       "Intl.v8BreakIterator");
}

BUILTIN(V8BreakIteratorPrototypeResolvedOptions) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSV8BreakIterator, break_iterator,
                 "Intl.v8BreakIterator.prototype.resolvedOptions");
  return *JSV8BreakIterator::ResolvedOptions(isolate, break_iterator);
}

BUILTIN(V8BreakIteratorPrototypeAdoptText) {
  const char* const method_name =
      "get Intl.v8BreakIterator.prototype.adoptText";
  HandleScope scope(isolate);

  CHECK_RECEIVER(JSV8BreakIterator, break_iterator, method_name);

  DirectHandle<Object> bound_adopt_text(break_iterator->bound_adopt_text(),
                                        isolate);
  if (!IsUndefined(*bound_adopt_text, isolate)) {
    DCHECK(IsJSFunction(*bound_adopt_text));
    return *bound_adopt_text;
  }

  DirectHandle<JSFunction> new_bound_adopt_text_function = CreateBoundFunction(
      isolate, break_iterator, Builtin::kV8BreakIteratorInternalAdoptText, 1);
  break_iterator->set_bound_adopt_text(*new_bound_adopt_text_function);
  return *new_bound_adopt_text_function;
}

BUILTIN(V8BreakIteratorInternalAdoptText) {
  HandleScope scope(isolate);
  DirectHandle<Context> context(isolate->context(), isolate);

  DirectHandle<JSV8BreakIterator> break_iterator(
      Cast<JSV8BreakIterator>(context->get(
          static_cast<int>(Intl::BoundFunctionContextSlot::kBoundFunction))),
      isolate);

  Handle<Object> input_text = args.atOrUndefined(isolate, 1);
  Handle<String> text;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, text,
                                     Object::ToString(isolate, input_text));

  JSV8BreakIterator::AdoptText(isolate, break_iterator, text);
  return ReadOnlyRoots(isolate).undefined_value();
}

BUILTIN(V8BreakIteratorPrototypeFirst) {
  const char* const method_name = "get Intl.v8BreakIterator.prototype.first";
  HandleScope scope(isolate);

  CHECK_RECEIVER(JSV8BreakIterator, break_iterator, method_name);

  DirectHandle<Object> bound_first(break_iterator->bound_first(), isolate);
  if (!IsUndefined(*bound_first, isolate)) {
    DCHECK(IsJSFunction(*bound_first));
    return *bound_first;
  }

  DirectHandle<JSFunction> new_bound_first_function = CreateBoundFunction(
      isolate, break_iterator, Builtin::kV8BreakIteratorInternalFirst, 0);
  break_iterator->set_bound_first(*new_bound_first_function);
  return *new_bound_first_function;
}

BUILTIN(V8BreakIteratorInternalFirst) {
  HandleScope scope(isolate);
  DirectHandle<Context> context(isolate->context(), isolate);

  DirectHandle<JSV8BreakIterator> break_iterator(
      Cast<JSV8BreakIterator>(context->get(
          static_cast<int>(Intl::BoundFunctionContextSlot::kBoundFunction))),
      isolate);

  return *JSV8BreakIterator::First(isolate, break_iterator);
}

BUILTIN(V8BreakIteratorPrototypeNext) {
  const char* const method_name = "get Intl.v8BreakIterator.prototype.next";
  HandleScope scope(isolate);

  CHECK_RECEIVER(JSV8BreakIterator, break_iterator, method_name);

  DirectHandle<Object> bound_next(break_iterator->bound_next(), isolate);
  if (!IsUndefined(*bound_next, isolate)) {
    DCHECK(IsJSFunction(*bound_next));
    return *bound_next;
  }

  DirectHandle<JSFunction> new_bound_next_function = CreateBoundFunction(
      isolate, break_iterator, Builtin::kV8BreakIteratorInternalNext, 0);
  break_iterator->set_bound_next(*new_bound_next_function);
  return *new_bound_next_function;
}

BUILTIN(V8BreakIteratorInternalNext) {
  HandleScope scope(isolate);
  DirectHandle<Context> context(isolate->context(), isolate);

  DirectHandle<JSV8BreakIterator> break_iterator(
      Cast<JSV8BreakIterator>(context->get(
          static_cast<int>(Intl::BoundFunctionContextSlot::kBoundFunction))),
      isolate);
  return *JSV8BreakIterator::Next(isolate, break_iterator);
}

BUILTIN(V8BreakIteratorPrototypeCurrent) {
  const char* const method_name = "get Intl.v8BreakIterator.prototype.current";
  HandleScope scope(isolate);

  CHECK_RECEIVER(JSV8BreakIterator, break_iterator, method_name);

  DirectHandle<Object> bound_current(break_iterator->bound_current(), isolate);
  if (!IsUndefined(*bound_current, isolate)) {
    DCHECK(IsJSFunction(*bound_current));
    return *bound_current;
  }

  DirectHandle<JSFunction> new_bound_current_function = CreateBoundFunction(
      isolate, break_iterator, Builtin::kV8BreakIteratorInternalCurrent, 0);
  break_iterator->set_bound_current(*new_bound_current_function);
  return *new_bound_current_function;
}

BUILTIN(V8BreakIteratorInternalCurrent) {
  HandleScope scope(isolate);
  DirectHandle<Context> context(isolate->context(), isolate);

  DirectHandle<JSV8BreakIterator> break_iterator(
      Cast<JSV8BreakIterator>(context->get(
          static_cast<int>(Intl::BoundFunctionContextSlot::kBoundFunction))),
      isolate);
  return *JSV8BreakIterator::Current(isolate, break_iterator);
}

BUILTIN(V8BreakIteratorPrototypeBreakType) {
  const char* const method_name =
      "get Intl.v8BreakIterator.prototype.breakType";
  HandleScope scope(isolate);

  CHECK_RECEIVER(JSV8BreakIterator, break_iterator, method_name);

  DirectHandle<Object> bound_break_type(break_iterator->bound_break_type(),
                                        isolate);
  if (!IsUndefined(*bound_break_type, isolate)) {
    DCHECK(IsJSFunction(*bound_break_type));
    return *bound_break_type;
  }

  DirectHandle<JSFunction> new_bound_break_type_function = CreateBoundFunction(
      isolate, break_iterator, Builtin::kV8BreakIteratorInternalBreakType, 0);
  break_iterator->set_bound_break_type(*new_bound_break_type_function);
  return *new_bound_break_type_function;
}

BUILTIN(V8BreakIteratorInternalBreakType) {
  HandleScope scope(isolate);
  DirectHandle<Context> context(isolate->context(), isolate);

  DirectHandle<JSV8BreakIterator> break_iterator(
      Cast<JSV8BreakIterator>(context->get(
          static_cast<int>(Intl::BoundFunctionContextSlot::kBoundFunction))),
      isolate);
  return JSV8BreakIterator::BreakType(isolate, break_iterator);
}

}  // namespace internal
}  // namespace v8

"""


```