Response: The user wants me to summarize the functionality of the C++ code provided in the second part of the `intl-objects.cc` file. I also need to illustrate its connection to JavaScript using examples.

**Plan:**

1. **High-level overview:** Identify the main areas of functionality covered in this code snippet. It seems to be focused on locale handling, time zone operations, and number formatting.
2. **Detailed breakdown:** Go through the code blocks and describe the purpose of each function and code section.
3. **Identify JavaScript connections:** Determine which JavaScript Intl API features are implemented or supported by this C++ code.
4. **Provide JavaScript examples:** Create simple JavaScript code snippets that demonstrate the usage of the identified Intl API features and how they relate to the C++ code.
This C++ code snippet from `v8/src/objects/intl-objects.cc` focuses on implementing several functionalities related to internationalization (Intl) in JavaScript. It deals with:

*   **Locale Handling:**  This includes finding the best matching locale from a list of available locales based on user preferences, canonicalizing locale strings, looking up supported locales, and handling locale extensions (like calendar or collation).
*   **Time Zone Operations:** It provides functions for retrieving canonical time zone names, checking if a time zone name is valid, getting the default time zone, and importantly, handling time zone transitions and offsets, which is crucial for the `Temporal` API.
*   **Supported Values of Intl Options:**  It implements the logic for `Intl.supportedValuesOf`, allowing JavaScript to query the available values for various Intl options like calendar, collation, currency, numbering system, time zone, and unit.
*   **Normalization:** It includes functionality for string normalization as used by `String.prototype.normalize()`.
*   **Internal Utilities:** It provides various helper functions for converting between JavaScript and ICU data types (like strings), creating JavaScript arrays from C++ data structures, and managing ICU objects.
*   **Number Formatting Internals (Indirectly):** While the initial part of the snippet deals with `NumberFormatDigitOptions`, this section mainly handles locale resolution and other supporting functionalities for number formatting. The direct formatting logic would be in other parts of the file.

**Relationship with JavaScript and Examples:**

This C++ code directly implements the underlying logic for various JavaScript Intl APIs. When you use these APIs in JavaScript, the V8 engine (which includes this C++ code) executes the corresponding C++ functions.

Here are some JavaScript examples illustrating the connection:

**1. `Intl.getCanonicalLocales()`:**

```javascript
const locales = ['en-US-u-co-phonebk', 'zh-CN'];
const canonicalLocales = Intl.getCanonicalLocales(locales);
console.log(canonicalLocales); // Output might be: [ 'en-US-u-co-phonebk', 'zh-CN' ] (the order might not be guaranteed)
```

The C++ function `Intl::GetCanonicalLocales` processes the input locale strings and returns a canonicalized array. The `ParseBCP47Locale` function in the C++ code is involved in understanding the structure of the locale strings, including any Unicode extensions.

**2. `Intl.supportedValuesOf()`:**

```javascript
const availableCalendars = Intl.supportedValuesOf('calendar');
console.log(availableCalendars.includes('gregory')); // Output: true (depending on ICU version)

const availableCurrencies = Intl.supportedValuesOf('currency');
console.log(availableCurrencies.includes('USD')); // Output: true
```

The C++ function `Intl::SupportedValuesOf` is called here. For example, when `'calendar'` is passed, the C++ function `Intl::AvailableCalendars` (not shown in this snippet but likely in the first part) or `AvailableCalendars` within this snippet is invoked to fetch the available calendar types. Similarly, `AvailableCurrencies` is called for `'currency'`.

**3. `Intl.supportedLocalesOf()`:**

```javascript
const supported = Intl.NumberFormat.supportedLocalesOf(['fr-CA', 'en-GB'], { localeMatcher: 'lookup' });
console.log(supported); // Output might be: [ 'fr-CA', 'en-GB' ]

const bestFitSupported = Intl.DateTimeFormat.supportedLocalesOf(['de-DE-u-hc-h24', 'ja-JP'], { localeMatcher: 'best fit' });
console.log(bestFitSupported); // Output will depend on the available locales and the best-fit algorithm.
```

The C++ function `Intl::SupportedLocalesOf` is the core implementation. It calls either `LookupSupportedLocales` or `BestFitSupportedLocales` based on the `localeMatcher` option. The `BestAvailableLocale` function is a key component in determining the best matching locale.

**4. `String.prototype.normalize()`:**

```javascript
const str = '\u00C5'; // Å (Latin capital letter A with ring above)
const nfc = str.normalize('NFC');
console.log(nfc); // Output: 'Å' (already in NFC)

const nfd = str.normalize('NFD');
console.log(nfd); // Output: 'Å' (A followed by combining ring above)
```

The C++ function `Intl::Normalize` implements the different normalization forms (NFC, NFD, NFKC, NFKD) using ICU's normalization functionalities.

**5. `Temporal` API (Time Zone Transitions and Offsets):**

```javascript
const tz = new Temporal.TimeZone('America/Los_Angeles');
const instant = Temporal.Instant.fromEpochSeconds(0); // The Unix epoch
const transition = tz.getNextTransition(instant);
console.log(transition); // Output: Information about the next time zone transition.

const offset = tz.getOffsetStringFor(instant);
console.log(offset); // Output: The offset string for that instant (e.g., '-08:00').
```

The C++ functions like `Intl::GetTimeZoneOffsetTransitionNanoseconds` and `Intl::GetTimeZoneOffsetNanoseconds` are crucial for the `Temporal` API's time zone functionality. They interact with ICU to retrieve accurate time zone transition information and offsets. The `ApproximateMillisecondEpoch` and `MillisecondToNanosecond` functions are used to bridge the gap between ICU's millisecond-based time and Temporal's nanosecond-based time.

In summary, this C++ code snippet is a vital part of V8's implementation of the JavaScript Intl API, providing the core logic for locale negotiation, time zone handling, and accessing internationalization data. It directly powers the behavior you observe when using Intl objects and related methods in your JavaScript code.

### 提示词
```
这是目录为v8/src/objects/intl-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
true.
  bool need_fd = true;
  // 23. If roundingPriority is "auto", then
  if (RoundingPriority::kAuto == digit_options.rounding_priority) {
    // a. Set needSd to hasSd.
    need_sd = has_sd;
    // b. If needSd is true, or hasFd is false and notation is "compact", then
    if (need_sd || ((!has_fd) && notation_is_compact)) {
      // i. Set needFd to false.
      need_fd = false;
    }
  }
  // 24. If needSd is true, then
  if (need_sd) {
    // 24.a If hasSd is true, then
    if (has_sd) {
      // i. Set intlObj.[[MinimumSignificantDigits]] to ?
      // DefaultNumberOption(mnsd, 1, 21, 1).
      int mnsd;
      if (!DefaultNumberOption(isolate, mnsd_obj, 1, 21, 1,
                               factory->minimumSignificantDigits_string())
               .To(&mnsd)) {
        return Nothing<NumberFormatDigitOptions>();
      }
      digit_options.minimum_significant_digits = mnsd;
      // ii. Set intlObj.[[MaximumSignificantDigits]] to ?
      // DefaultNumberOption(mxsd, intlObj.[[MinimumSignificantDigits]], 21,
      // 21).
      int mxsd;
      if (!DefaultNumberOption(isolate, mxsd_obj, mnsd, 21, 21,
                               factory->maximumSignificantDigits_string())
               .To(&mxsd)) {
        return Nothing<NumberFormatDigitOptions>();
      }
      digit_options.maximum_significant_digits = mxsd;
    } else {
      // 24.b Else
      // 24.b.i Set intlObj.[[MinimumSignificantDigits]] to 1.
      digit_options.minimum_significant_digits = 1;
      // 24.b.ii Set intlObj.[[MaximumSignificantDigits]] to 21.
      digit_options.maximum_significant_digits = 21;
    }
  }

  Handle<String> mxfd_str = factory->maximumFractionDigits_string();
  // 25. If needFd is true, then
  if (need_fd) {
    // a. If hasFd is true, then
    if (has_fd) {
      Handle<String> mnfd_str = factory->minimumFractionDigits_string();
      // i. Let mnfd be ? DefaultNumberOption(mnfd, 0, 100, undefined).
      int mnfd;
      if (!DefaultNumberOption(isolate, mnfd_obj, 0, 100, -1, mnfd_str)
               .To(&mnfd)) {
        return Nothing<NumberFormatDigitOptions>();
      }
      // ii. Let mxfd be ? DefaultNumberOption(mxfd, 0, 100, undefined).
      int mxfd;
      if (!DefaultNumberOption(isolate, mxfd_obj, 0, 100, -1, mxfd_str)
               .To(&mxfd)) {
        return Nothing<NumberFormatDigitOptions>();
      }
      // iii. If mnfd is undefined, set mnfd to min(mnfdDefault, mxfd).
      if (IsUndefined(*mnfd_obj, isolate)) {
        mnfd = std::min(mnfd_default, mxfd);
      } else if (IsUndefined(*mxfd_obj, isolate)) {
        // iv. Else if mxfd is undefined, set mxfd to max(mxfdDefault,
        // mnfd).
        mxfd = std::max(mxfd_default, mnfd);
      } else if (mnfd > mxfd) {
        // v. Else if mnfd is greater than mxfd, throw a RangeError
        // exception.
        THROW_NEW_ERROR_RETURN_VALUE(
            isolate,
            NewRangeError(MessageTemplate::kPropertyValueOutOfRange, mxfd_str),
            Nothing<NumberFormatDigitOptions>());
      }
      // vi. Set intlObj.[[MinimumFractionDigits]] to mnfd.
      digit_options.minimum_fraction_digits = mnfd;
      // vii. Set intlObj.[[MaximumFractionDigits]] to mxfd.
      digit_options.maximum_fraction_digits = mxfd;
    } else {  // b. Else
      // i. Set intlObj.[[MinimumFractionDigits]] to mnfdDefault.
      digit_options.minimum_fraction_digits = mnfd_default;
      // ii. Set intlObj.[[MaximumFractionDigits]] to mxfdDefault.
      digit_options.maximum_fraction_digits = mxfd_default;
    }
  }

  // 26. If needSd is false and needFd is false, then
  if ((!need_sd) && (!need_fd)) {
    // a. Set intlObj.[[MinimumFractionDigits]] to 0.
    digit_options.minimum_fraction_digits = 0;
    // b. Set intlObj.[[MaximumFractionDigits]] to 0.
    digit_options.maximum_fraction_digits = 0;
    // c. Set intlObj.[[MinimumSignificantDigits]] to 1.
    digit_options.minimum_significant_digits = 1;
    // d. Set intlObj.[[MaximumSignificantDigits]] to 2.
    digit_options.maximum_significant_digits = 2;
    // e. Set intlObj.[[RoundingType]] to morePrecision.
    digit_options.rounding_type = RoundingType::kMorePrecision;
    // 27. Else if roundingPriority is "morePrecision", then
  } else if (digit_options.rounding_priority ==
             RoundingPriority::kMorePrecision) {
    // i. Set intlObj.[[RoundingType]] to morePrecision.
    digit_options.rounding_type = RoundingType::kMorePrecision;
    // 28. Else if roundingPriority is "lessPrecision", then
  } else if (digit_options.rounding_priority ==
             RoundingPriority::kLessPrecision) {
    // i. Set intlObj.[[RoundingType]] to lessPrecision.
    digit_options.rounding_type = RoundingType::kLessPrecision;
    // 29. Else if hasSd, then
  } else if (has_sd) {
    // i. Set intlObj.[[RoundingType]] to significantDigits.
    digit_options.rounding_type = RoundingType::kSignificantDigits;
    // 30. Else,
  } else {
    // i.Set intlObj.[[RoundingType]] to fractionDigits.
    digit_options.rounding_type = RoundingType::kFractionDigits;
  }
  // 31. If roundingIncrement is not 1, then
  if (digit_options.rounding_increment != 1) {
    // a. If intlObj.[[RoundingType]] is not fractionDigits, throw a TypeError
    // exception.
    if (digit_options.rounding_type != RoundingType::kFractionDigits) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate, NewTypeError(MessageTemplate::kBadRoundingType),
          Nothing<NumberFormatDigitOptions>());
    }
    // b. If intlObj.[[MaximumFractionDigits]] is not equal to
    // intlObj.[[MinimumFractionDigits]], throw a RangeError exception.
    if (digit_options.maximum_fraction_digits !=
        digit_options.minimum_fraction_digits) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(MessageTemplate::kPropertyValueOutOfRange, mxfd_str),
          Nothing<NumberFormatDigitOptions>());
    }
  }
  return Just(digit_options);
}

namespace {

// ecma402/#sec-bestavailablelocale
std::string BestAvailableLocale(const std::set<std::string>& available_locales,
                                const std::string& locale) {
  // 1. Let candidate be locale.
  std::string candidate = locale;

  // 2. Repeat,
  while (true) {
    // 2.a. If availableLocales contains an element equal to candidate, return
    //      candidate.
    if (available_locales.find(candidate) != available_locales.end()) {
      return candidate;
    }

    // 2.b. Let pos be the character index of the last occurrence of "-"
    //      (U+002D) within candidate. If that character does not occur, return
    //      undefined.
    size_t pos = candidate.rfind('-');
    if (pos == std::string::npos) {
      return std::string();
    }

    // 2.c. If pos ≥ 2 and the character "-" occurs at index pos-2 of candidate,
    //      decrease pos by 2.
    if (pos >= 2 && candidate[pos - 2] == '-') {
      pos -= 2;
    }

    // 2.d. Let candidate be the substring of candidate from position 0,
    //      inclusive, to position pos, exclusive.
    candidate = candidate.substr(0, pos);
  }
}

struct ParsedLocale {
  std::string no_extensions_locale;
  std::string extension;
};

// Returns a struct containing a bcp47 tag without unicode extensions
// and the removed unicode extensions.
//
// For example, given 'en-US-u-co-emoji' returns 'en-US' and
// 'u-co-emoji'.
ParsedLocale ParseBCP47Locale(const std::string& locale) {
  size_t length = locale.length();
  ParsedLocale parsed_locale;

  // Privateuse or grandfathered locales have no extension sequences.
  if ((length > 1) && (locale[1] == '-')) {
    // Check to make sure that this really is a grandfathered or
    // privateuse extension. ICU can sometimes mess up the
    // canonicalization.
    DCHECK(locale[0] == 'x' || locale[0] == 'i');
    parsed_locale.no_extensions_locale = locale;
    return parsed_locale;
  }

  size_t unicode_extension_start = locale.find("-u-");

  // No unicode extensions found.
  if (unicode_extension_start == std::string::npos) {
    parsed_locale.no_extensions_locale = locale;
    return parsed_locale;
  }

  size_t private_extension_start = locale.find("-x-");

  // Unicode extensions found within privateuse subtags don't count.
  if (private_extension_start != std::string::npos &&
      private_extension_start < unicode_extension_start) {
    parsed_locale.no_extensions_locale = locale;
    return parsed_locale;
  }

  const std::string beginning = locale.substr(0, unicode_extension_start);
  size_t unicode_extension_end = length;
  DCHECK_GT(length, 2);

  // Find the end of the extension production as per the bcp47 grammar
  // by looking for '-' followed by 2 chars and then another '-'.
  for (size_t i = unicode_extension_start + 1; i < length - 2; i++) {
    if (locale[i] != '-') continue;

    if (locale[i + 2] == '-') {
      unicode_extension_end = i;
      break;
    }

    i += 2;
  }

  const std::string end = locale.substr(unicode_extension_end);
  parsed_locale.no_extensions_locale = beginning + end;
  parsed_locale.extension = locale.substr(
      unicode_extension_start, unicode_extension_end - unicode_extension_start);
  return parsed_locale;
}

// ecma402/#sec-lookupsupportedlocales
std::vector<std::string> LookupSupportedLocales(
    const std::set<std::string>& available_locales,
    const std::vector<std::string>& requested_locales) {
  // 1. Let subset be a new empty List.
  std::vector<std::string> subset;

  // 2. For each element locale of requestedLocales in List order, do
  for (const std::string& locale : requested_locales) {
    // 2. a. Let noExtensionsLocale be the String value that is locale
    //       with all Unicode locale extension sequences removed.
    std::string no_extension_locale =
        ParseBCP47Locale(locale).no_extensions_locale;

    // 2. b. Let availableLocale be
    //       BestAvailableLocale(availableLocales, noExtensionsLocale).
    std::string available_locale =
        BestAvailableLocale(available_locales, no_extension_locale);

    // 2. c. If availableLocale is not undefined, append locale to the
    //       end of subset.
    if (!available_locale.empty()) {
      subset.push_back(locale);
    }
  }

  // 3. Return subset.
  return subset;
}

icu::LocaleMatcher BuildLocaleMatcher(
    Isolate* isolate, const std::set<std::string>& available_locales,
    UErrorCode* status) {
  icu::Locale default_locale =
      icu::Locale::forLanguageTag(isolate->DefaultLocale(), *status);
  icu::LocaleMatcher::Builder builder;
  if (U_FAILURE(*status)) {
    return builder.build(*status);
  }
  builder.setDefaultLocale(&default_locale);
  for (auto it = available_locales.begin(); it != available_locales.end();
       ++it) {
    *status = U_ZERO_ERROR;
    icu::Locale l = icu::Locale::forLanguageTag(it->c_str(), *status);
    // skip invalid locale such as no-NO-NY
    if (U_SUCCESS(*status)) {
      builder.addSupportedLocale(l);
    }
  }
  return builder.build(*status);
}

class Iterator : public icu::Locale::Iterator {
 public:
  Iterator(std::vector<std::string>::const_iterator begin,
           std::vector<std::string>::const_iterator end)
      : iter_(begin), end_(end) {}
  ~Iterator() override = default;

  UBool hasNext() const override { return iter_ != end_; }

  const icu::Locale& next() override {
    UErrorCode status = U_ZERO_ERROR;
    locale_ = icu::Locale::forLanguageTag(iter_->c_str(), status);
    DCHECK(U_SUCCESS(status));
    ++iter_;
    return locale_;
  }

 private:
  std::vector<std::string>::const_iterator iter_;
  std::vector<std::string>::const_iterator end_;
  icu::Locale locale_;
};

// ecma402/#sec-bestfitmatcher
// The BestFitMatcher abstract operation compares requestedLocales, which must
// be a List as returned by CanonicalizeLocaleList, against the locales in
// availableLocales and determines the best available language to meet the
// request. The algorithm is implementation dependent, but should produce
// results that a typical user of the requested locales would perceive
// as at least as good as those produced by the LookupMatcher abstract
// operation. Options specified through Unicode locale extension sequences must
// be ignored by the algorithm. Information about such subsequences is returned
// separately. The abstract operation returns a record with a [[locale]] field,
// whose value is the language tag of the selected locale, which must be an
// element of availableLocales. If the language tag of the request locale that
// led to the selected locale contained a Unicode locale extension sequence,
// then the returned record also contains an [[extension]] field whose value is
// the first Unicode locale extension sequence within the request locale
// language tag.
std::string BestFitMatcher(Isolate* isolate,
                           const std::set<std::string>& available_locales,
                           const std::vector<std::string>& requested_locales) {
  UErrorCode status = U_ZERO_ERROR;
  Iterator iter(requested_locales.cbegin(), requested_locales.cend());
  std::string bestfit = BuildLocaleMatcher(isolate, available_locales, &status)
                            .getBestMatchResult(iter, status)
                            .makeResolvedLocale(status)
                            .toLanguageTag<std::string>(status);
  DCHECK(U_SUCCESS(status));
  return bestfit;
}

// ECMA 402 9.2.8 BestFitSupportedLocales(availableLocales, requestedLocales)
// https://tc39.github.io/ecma402/#sec-bestfitsupportedlocales
std::vector<std::string> BestFitSupportedLocales(
    Isolate* isolate, const std::set<std::string>& available_locales,
    const std::vector<std::string>& requested_locales) {
  UErrorCode status = U_ZERO_ERROR;
  icu::LocaleMatcher matcher =
      BuildLocaleMatcher(isolate, available_locales, &status);
  std::vector<std::string> result;
  if (U_SUCCESS(status)) {
    for (auto it = requested_locales.cbegin(); it != requested_locales.cend();
         it++) {
      status = U_ZERO_ERROR;
      icu::Locale desired = icu::Locale::forLanguageTag(it->c_str(), status);
      icu::LocaleMatcher::Result matched =
          matcher.getBestMatchResult(desired, status);
      if (U_FAILURE(status)) continue;
      if (matched.getSupportedIndex() < 0) continue;

      // The BestFitSupportedLocales abstract operation returns the *SUBSET* of
      // the provided BCP 47 language priority list requestedLocales for which
      // availableLocales has a matching locale when using the Best Fit Matcher
      // algorithm. Locales appear in the same order in the returned list as in
      // requestedLocales. The steps taken are implementation dependent.
      std::string bestfit = desired.toLanguageTag<std::string>(status);
      if (U_FAILURE(status)) continue;
      result.push_back(bestfit);
    }
  }
  return result;
}

// ecma262 #sec-createarrayfromlist
MaybeHandle<JSArray> CreateArrayFromList(Isolate* isolate,
                                         std::vector<std::string> elements,
                                         PropertyAttributes attr) {
  Factory* factory = isolate->factory();
  // Let array be ! ArrayCreate(0).
  Handle<JSArray> array = factory->NewJSArray(0);

  uint32_t length = static_cast<uint32_t>(elements.size());
  // 3. Let n be 0.
  // 4. For each element e of elements, do
  for (uint32_t i = 0; i < length; i++) {
    // a. Let status be CreateDataProperty(array, ! ToString(n), e).
    const std::string& part = elements[i];
    DirectHandle<String> value =
        factory->NewStringFromUtf8(base::CStrVector(part.c_str()))
            .ToHandleChecked();
    MAYBE_RETURN(JSObject::AddDataElement(array, i, value, attr),
                 MaybeHandle<JSArray>());
  }
  // 5. Return array.
  return MaybeHandle<JSArray>(array);
}

// ECMA 402 9.2.9 SupportedLocales(availableLocales, requestedLocales, options)
// https://tc39.github.io/ecma402/#sec-supportedlocales
MaybeHandle<JSObject> SupportedLocales(
    Isolate* isolate, const char* method_name,
    const std::set<std::string>& available_locales,
    const std::vector<std::string>& requested_locales, Handle<Object> options) {
  std::vector<std::string> supported_locales;

  // 1. Set options to ? CoerceOptionsToObject(options).
  Handle<JSReceiver> options_obj;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options_obj,
      CoerceOptionsToObject(isolate, options, method_name));

  // 2. Let matcher be ? GetOption(options, "localeMatcher", "string",
  //       « "lookup", "best fit" », "best fit").
  Maybe<Intl::MatcherOption> maybe_locale_matcher =
      Intl::GetLocaleMatcher(isolate, options_obj, method_name);
  MAYBE_RETURN(maybe_locale_matcher, MaybeHandle<JSObject>());
  Intl::MatcherOption matcher = maybe_locale_matcher.FromJust();

  // 3. If matcher is "best fit", then
  //    a. Let supportedLocales be BestFitSupportedLocales(availableLocales,
  //       requestedLocales).
  if (matcher == Intl::MatcherOption::kBestFit &&
      v8_flags.harmony_intl_best_fit_matcher) {
    supported_locales =
        BestFitSupportedLocales(isolate, available_locales, requested_locales);
  } else {
    // 4. Else,
    //    a. Let supportedLocales be LookupSupportedLocales(availableLocales,
    //       requestedLocales).
    supported_locales =
        LookupSupportedLocales(available_locales, requested_locales);
  }

  // 5. Return CreateArrayFromList(supportedLocales).
  return CreateArrayFromList(isolate, supported_locales,
                             PropertyAttributes::NONE);
}

}  // namespace

// ecma-402 #sec-intl.getcanonicallocales
MaybeHandle<JSArray> Intl::GetCanonicalLocales(Isolate* isolate,
                                               Handle<Object> locales) {
  // 1. Let ll be ? CanonicalizeLocaleList(locales).
  Maybe<std::vector<std::string>> maybe_ll =
      CanonicalizeLocaleList(isolate, locales, false);
  MAYBE_RETURN(maybe_ll, MaybeHandle<JSArray>());

  // 2. Return CreateArrayFromList(ll).
  return CreateArrayFromList(isolate, maybe_ll.FromJust(),
                             PropertyAttributes::NONE);
}

namespace {

MaybeHandle<JSArray> AvailableCollations(Isolate* isolate) {
  UErrorCode status = U_ZERO_ERROR;
  std::unique_ptr<icu::StringEnumeration> enumeration(
      icu::Collator::getKeywordValues("collation", status));
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  return Intl::ToJSArray(isolate, "co", enumeration.get(),
                         Intl::RemoveCollation, true);
}

MaybeHandle<JSArray> VectorToJSArray(Isolate* isolate,
                                     const std::vector<std::string>& array) {
  Factory* factory = isolate->factory();
  DirectHandle<FixedArray> fixed_array =
      factory->NewFixedArray(static_cast<int32_t>(array.size()));
  int32_t index = 0;
  for (const std::string& item : array) {
    DirectHandle<String> str = factory->NewStringFromAsciiChecked(item.c_str());
    fixed_array->set(index++, *str);
  }
  return factory->NewJSArrayWithElements(fixed_array);
}

namespace {

class ResourceAvailableCurrencies {
 public:
  ResourceAvailableCurrencies() {
    UErrorCode status = U_ZERO_ERROR;
    UEnumeration* uenum =
        ucurr_openISOCurrencies(UCURR_COMMON | UCURR_NON_DEPRECATED, &status);
    DCHECK(U_SUCCESS(status));
    const char* next = nullptr;
    while (U_SUCCESS(status) &&
           (next = uenum_next(uenum, nullptr, &status)) != nullptr) {
      // Work around the issue that we do not support VEF currency code
      // in DisplayNames by not reporting it.
      if (strcmp(next, "VEF") == 0) continue;
      AddIfAvailable(next);
    }
    // Work around the issue that we do support the following currency codes
    // in DisplayNames but the ICU API is not reporting it.
    AddIfAvailable("SVC");
    AddIfAvailable("XDR");
    AddIfAvailable("XSU");
    AddIfAvailable("ZWL");
    std::sort(list_.begin(), list_.end());
    uenum_close(uenum);
  }

  const std::vector<std::string>& Get() const { return list_; }

  void AddIfAvailable(const char* currency) {
    icu::UnicodeString code(currency, -1, US_INV);
    UErrorCode status = U_ZERO_ERROR;
    int32_t len = 0;
    const UChar* result =
        ucurr_getName(code.getTerminatedBuffer(), "en", UCURR_LONG_NAME,
                      nullptr, &len, &status);
    if (U_SUCCESS(status) &&
        u_strcmp(result, code.getTerminatedBuffer()) != 0) {
      list_.push_back(currency);
    }
  }

 private:
  std::vector<std::string> list_;
};

const std::vector<std::string>& GetAvailableCurrencies() {
  static base::LazyInstance<ResourceAvailableCurrencies>::type
      available_currencies = LAZY_INSTANCE_INITIALIZER;
  return available_currencies.Pointer()->Get();
}
}  // namespace

MaybeHandle<JSArray> AvailableCurrencies(Isolate* isolate) {
  return VectorToJSArray(isolate, GetAvailableCurrencies());
}

MaybeHandle<JSArray> AvailableNumberingSystems(Isolate* isolate) {
  UErrorCode status = U_ZERO_ERROR;
  std::unique_ptr<icu::StringEnumeration> enumeration(
      icu::NumberingSystem::getAvailableNames(status));
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  // Need to filter out isAlgorithmic
  return Intl::ToJSArray(
      isolate, "nu", enumeration.get(),
      [](const char* value) {
        UErrorCode status = U_ZERO_ERROR;
        std::unique_ptr<icu::NumberingSystem> numbering_system(
            icu::NumberingSystem::createInstanceByName(value, status));
        // Skip algorithmic one since chrome filter out the resource.
        return U_FAILURE(status) || numbering_system->isAlgorithmic();
      },
      true);
}

MaybeHandle<JSArray> AvailableTimeZones(Isolate* isolate) {
  UErrorCode status = U_ZERO_ERROR;
  std::unique_ptr<icu::StringEnumeration> enumeration(
      icu::TimeZone::createTimeZoneIDEnumeration(
          UCAL_ZONE_TYPE_CANONICAL_LOCATION, nullptr, nullptr, status));
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  return Intl::ToJSArray(isolate, nullptr, enumeration.get(), nullptr, true);
}

MaybeHandle<JSArray> AvailableUnits(Isolate* isolate) {
  Factory* factory = isolate->factory();
  std::set<std::string> sanctioned(Intl::SanctionedSimpleUnits());
  DirectHandle<FixedArray> fixed_array =
      factory->NewFixedArray(static_cast<int32_t>(sanctioned.size()));
  int32_t index = 0;
  for (const std::string& item : sanctioned) {
    DirectHandle<String> str = factory->NewStringFromAsciiChecked(item.c_str());
    fixed_array->set(index++, *str);
  }
  return factory->NewJSArrayWithElements(fixed_array);
}

}  // namespace

// ecma-402 #sec-intl.supportedvaluesof
MaybeHandle<JSArray> Intl::SupportedValuesOf(Isolate* isolate,
                                             Handle<Object> key_obj) {
  Factory* factory = isolate->factory();
  // 1. 1. Let key be ? ToString(key).
  Handle<String> key_str;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, key_str,
                             Object::ToString(isolate, key_obj));
  // 2. If key is "calendar", then
  if (factory->calendar_string()->Equals(*key_str)) {
    // a. Let list be ! AvailableCalendars( ).
    return Intl::AvailableCalendars(isolate);
  }
  // 3. Else if key is "collation", then
  if (factory->collation_string()->Equals(*key_str)) {
    // a. Let list be ! AvailableCollations( ).
    return AvailableCollations(isolate);
  }
  // 4. Else if key is "currency", then
  if (factory->currency_string()->Equals(*key_str)) {
    // a. Let list be ! AvailableCurrencies( ).
    return AvailableCurrencies(isolate);
  }
  // 5. Else if key is "numberingSystem", then
  if (factory->numberingSystem_string()->Equals(*key_str)) {
    // a. Let list be ! AvailableNumberingSystems( ).
    return AvailableNumberingSystems(isolate);
  }
  // 6. Else if key is "timeZone", then
  if (factory->timeZone_string()->Equals(*key_str)) {
    // a. Let list be ! AvailableTimeZones( ).
    return AvailableTimeZones(isolate);
  }
  // 7. Else if key is "unit", then
  if (factory->unit_string()->Equals(*key_str)) {
    // a. Let list be ! AvailableUnits( ).
    return AvailableUnits(isolate);
  }
  // 8. Else,
  // a. Throw a RangeError exception.
  // 9. Return ! CreateArrayFromList( list ).

  THROW_NEW_ERROR(
      isolate,
      NewRangeError(MessageTemplate::kInvalid,
                    factory->NewStringFromStaticChars("key"), key_str));
}

// ECMA 402 Intl.*.supportedLocalesOf
MaybeHandle<JSObject> Intl::SupportedLocalesOf(
    Isolate* isolate, const char* method_name,
    const std::set<std::string>& available_locales, Handle<Object> locales,
    Handle<Object> options) {
  // Let availableLocales be %Collator%.[[AvailableLocales]].

  // Let requestedLocales be ? CanonicalizeLocaleList(locales).
  Maybe<std::vector<std::string>> requested_locales =
      CanonicalizeLocaleList(isolate, locales, false);
  MAYBE_RETURN(requested_locales, MaybeHandle<JSObject>());

  // Return ? SupportedLocales(availableLocales, requestedLocales, options).
  return SupportedLocales(isolate, method_name, available_locales,
                          requested_locales.FromJust(), options);
}

namespace {

template <typename T>
bool IsValidExtension(const icu::Locale& locale, const char* key,
                      const std::string& value) {
  const char* legacy_type = uloc_toLegacyType(key, value.c_str());
  if (legacy_type == nullptr) {
    return false;
  }
  UErrorCode status = U_ZERO_ERROR;
  std::unique_ptr<icu::StringEnumeration> enumeration(
      T::getKeywordValuesForLocale(key, icu::Locale(locale.getBaseName()),
                                   false, status));
  if (U_FAILURE(status)) {
    return false;
  }
  int32_t length;
  for (const char* item = enumeration->next(&length, status);
       U_SUCCESS(status) && item != nullptr;
       item = enumeration->next(&length, status)) {
    if (strcmp(legacy_type, item) == 0) {
      return true;
    }
  }
  return false;
}

}  // namespace

bool Intl::IsValidCollation(const icu::Locale& locale,
                            const std::string& value) {
  std::set<std::string> invalid_values = {"standard", "search"};
  if (invalid_values.find(value) != invalid_values.end()) return false;
  return IsValidExtension<icu::Collator>(locale, "collation", value);
}

bool Intl::IsWellFormedCalendar(const std::string& value) {
  return JSLocale::Is38AlphaNumList(value);
}

// ecma402/#sec-iswellformedcurrencycode
bool Intl::IsWellFormedCurrency(const std::string& currency) {
  return JSLocale::Is3Alpha(currency);
}

bool Intl::IsValidCalendar(const icu::Locale& locale,
                           const std::string& value) {
  return IsValidExtension<icu::Calendar>(locale, "calendar", value);
}

bool Intl::IsValidNumberingSystem(const std::string& value) {
  std::set<std::string> invalid_values = {"native", "traditio", "finance"};
  if (invalid_values.find(value) != invalid_values.end()) return false;
  UErrorCode status = U_ZERO_ERROR;
  std::unique_ptr<icu::NumberingSystem> numbering_system(
      icu::NumberingSystem::createInstanceByName(value.c_str(), status));
  return U_SUCCESS(status) && numbering_system != nullptr &&
         !numbering_system->isAlgorithmic();
}

namespace {

bool IsWellFormedNumberingSystem(const std::string& value) {
  return JSLocale::Is38AlphaNumList(value);
}

std::map<std::string, std::string> LookupAndValidateUnicodeExtensions(
    icu::Locale* icu_locale, const std::set<std::string>& relevant_keys) {
  std::map<std::string, std::string> extensions;

  UErrorCode status = U_ZERO_ERROR;
  icu::LocaleBuilder builder;
  builder.setLocale(*icu_locale).clearExtensions();
  std::unique_ptr<icu::StringEnumeration> keywords(
      icu_locale->createKeywords(status));
  if (U_FAILURE(status)) return extensions;

  if (!keywords) return extensions;
  char value[ULOC_FULLNAME_CAPACITY];

  int32_t length;
  status = U_ZERO_ERROR;
  for (const char* keyword = keywords->next(&length, status);
       keyword != nullptr; keyword = keywords->next(&length, status)) {
    // Ignore failures in ICU and skip to the next keyword.
    //
    // This is fine.™
    if (U_FAILURE(status)) {
      status = U_ZERO_ERROR;
      continue;
    }

    icu_locale->getKeywordValue(keyword, value, ULOC_FULLNAME_CAPACITY, status);

    // Ignore failures in ICU and skip to the next keyword.
    //
    // This is fine.™
    if (U_FAILURE(status)) {
      status = U_ZERO_ERROR;
      continue;
    }

    const char* bcp47_key = uloc_toUnicodeLocaleKey(keyword);

    if (bcp47_key && (relevant_keys.find(bcp47_key) != relevant_keys.end())) {
      const char* bcp47_value = uloc_toUnicodeLocaleType(bcp47_key, value);
      bool is_valid_value = false;
      // 8.h.ii.1.a If keyLocaleData contains requestedValue, then
      if (strcmp("ca", bcp47_key) == 0) {
        is_valid_value = Intl::IsValidCalendar(*icu_locale, bcp47_value);
      } else if (strcmp("co", bcp47_key) == 0) {
        is_valid_value = Intl::IsValidCollation(*icu_locale, bcp47_value);
      } else if (strcmp("hc", bcp47_key) == 0) {
        // https://www.unicode.org/repos/cldr/tags/latest/common/bcp47/calendar.xml
        std::set<std::string> valid_values = {"h11", "h12", "h23", "h24"};
        is_valid_value = valid_values.find(bcp47_value) != valid_values.end();
      } else if (strcmp("lb", bcp47_key) == 0) {
        // https://www.unicode.org/repos/cldr/tags/latest/common/bcp47/segmentation.xml
        std::set<std::string> valid_values = {"strict", "normal", "loose"};
        is_valid_value = valid_values.find(bcp47_value) != valid_values.end();
      } else if (strcmp("kn", bcp47_key) == 0) {
        // https://www.unicode.org/repos/cldr/tags/latest/common/bcp47/collation.xml
        std::set<std::string> valid_values = {"true", "false"};
        is_valid_value = valid_values.find(bcp47_value) != valid_values.end();
      } else if (strcmp("kf", bcp47_key) == 0) {
        // https://www.unicode.org/repos/cldr/tags/latest/common/bcp47/collation.xml
        std::set<std::string> valid_values = {"upper", "lower", "false"};
        is_valid_value = valid_values.find(bcp47_value) != valid_values.end();
      } else if (strcmp("nu", bcp47_key) == 0) {
        is_valid_value = Intl::IsValidNumberingSystem(bcp47_value);
      }
      if (is_valid_value) {
        extensions.insert(
            std::pair<std::string, std::string>(bcp47_key, bcp47_value));
        builder.setUnicodeLocaleKeyword(bcp47_key, bcp47_value);
      }
    }
  }

  status = U_ZERO_ERROR;
  *icu_locale = builder.build(status);

  return extensions;
}

// ecma402/#sec-lookupmatcher
std::string LookupMatcher(Isolate* isolate,
                          const std::set<std::string>& available_locales,
                          const std::vector<std::string>& requested_locales) {
  // 1. Let result be a new Record.
  std::string result;

  // 2. For each element locale of requestedLocales in List order, do
  for (const std::string& locale : requested_locales) {
    // 2. a. Let noExtensionsLocale be the String value that is locale
    //       with all Unicode locale extension sequences removed.
    ParsedLocale parsed_locale = ParseBCP47Locale(locale);
    std::string no_extensions_locale = parsed_locale.no_extensions_locale;

    // 2. b. Let availableLocale be
    //       BestAvailableLocale(availableLocales, noExtensionsLocale).
    std::string available_locale =
        BestAvailableLocale(available_locales, no_extensions_locale);

    // 2. c. If availableLocale is not undefined, append locale to the
    //       end of subset.
    if (!available_locale.empty()) {
      // Note: The following steps are not performed here because we
      // can use ICU to parse the unicode locale extension sequence
      // as part of Intl::ResolveLocale.
      //
      // There's no need to separate the unicode locale extensions
      // right here. Instead just return the available locale with the
      // extensions.
      //
      // 2. c. i. Set result.[[locale]] to availableLocale.
      // 2. c. ii. If locale and noExtensionsLocale are not the same
      // String value, then
      // 2. c. ii. 1. Let extension be the String value consisting of
      // the first substring of locale that is a Unicode locale
      // extension sequence.
      // 2. c. ii. 2. Set result.[[extension]] to extension.
      // 2. c. iii. Return result.
      return available_locale + parsed_locale.extension;
    }
  }

  // 3. Let defLocale be DefaultLocale();
  // 4. Set result.[[locale]] to defLocale.
  // 5. Return result.
  return isolate->DefaultLocale();
}

}  // namespace

// This function doesn't correspond exactly with the spec. Instead
// we use ICU to do all the string manipulations that the spec
// peforms.
//
// The spec uses this function to normalize values for various
// relevant extension keys (such as disallowing "search" for
// collation). Instead of doing this here, we let the callers of
// this method perform such normalization.
//
// ecma402/#sec-resolvelocale
Maybe<Intl::ResolvedLocale> Intl::ResolveLocale(
    Isolate* isolate, const std::set<std::string>& available_locales,
    const std::vector<std::string>& requested_locales, MatcherOption matcher,
    const std::set<std::string>& relevant_extension_keys) {
  std::string locale;
  if (matcher == Intl::MatcherOption::kBestFit &&
      v8_flags.harmony_intl_best_fit_matcher) {
    locale = BestFitMatcher(isolate, available_locales, requested_locales);
  } else {
    locale = LookupMatcher(isolate, available_locales, requested_locales);
  }

  Maybe<icu::Locale> maybe_icu_locale = CreateICULocale(locale);
  MAYBE_RETURN(maybe_icu_locale, Nothing<Intl::ResolvedLocale>());
  icu::Locale icu_locale = maybe_icu_locale.FromJust();
  std::map<std::string, std::string> extensions =
      LookupAndValidateUnicodeExtensions(&icu_locale, relevant_extension_keys);

  std::string canonicalized_locale = Intl::ToLanguageTag(icu_locale).FromJust();

  // TODO(gsathya): Remove privateuse subtags from extensions.

  return Just(
      Intl::ResolvedLocale{canonicalized_locale, icu_locale, extensions});
}

Handle<Managed<icu::UnicodeString>> Intl::SetTextToBreakIterator(
    Isolate* isolate, Handle<String> text, icu::BreakIterator* break_iterator) {
  text = String::Flatten(isolate, text);
  std::shared_ptr<icu::UnicodeString> u_text{static_cast<icu::UnicodeString*>(
      Intl::ToICUUnicodeString(isolate, text).clone())};

  Handle<Managed<icu::UnicodeString>> new_u_text =
      Managed<icu::UnicodeString>::From(isolate, 0, u_text);

  break_iterator->setText(*u_text);
  return new_u_text;
}

// ecma262 #sec-string.prototype.normalize
MaybeHandle<String> Intl::Normalize(Isolate* isolate, Handle<String> string,
                                    Handle<Object> form_input) {
  const char* form_name;
  UNormalization2Mode form_mode;
  if (IsUndefined(*form_input, isolate)) {
    // default is FNC
    form_name = "nfc";
    form_mode = UNORM2_COMPOSE;
  } else {
    Handle<String> form;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, form,
                               Object::ToString(isolate, form_input));

    if (String::Equals(isolate, form, isolate->factory()->NFC_string())) {
      form_name = "nfc";
      form_mode = UNORM2_COMPOSE;
    } else if (String::Equals(isolate, form,
                              isolate->factory()->NFD_string())) {
      form_name = "nfc";
      form_mode = UNORM2_DECOMPOSE;
    } else if (String::Equals(isolate, form,
                              isolate->factory()->NFKC_string())) {
      form_name = "nfkc";
      form_mode = UNORM2_COMPOSE;
    } else if (String::Equals(isolate, form,
                              isolate->factory()->NFKD_string())) {
      form_name = "nfkc";
      form_mode = UNORM2_DECOMPOSE;
    } else {
      Handle<String> valid_forms =
          isolate->factory()->NewStringFromStaticChars("NFC, NFD, NFKC, NFKD");
      THROW_NEW_ERROR(
          isolate,
          NewRangeError(MessageTemplate::kNormalizationForm, valid_forms));
    }
  }

  uint32_t length = string->length();
  string = String::Flatten(isolate, string);
  icu::UnicodeString result;
  std::unique_ptr<base::uc16[]> sap;
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString input = ToICUUnicodeString(isolate, string);
  // Getting a singleton. Should not free it.
  const icu::Normalizer2* normalizer =
      icu::Normalizer2::getInstance(nullptr, form_name, form_mode, status);
  DCHECK(U_SUCCESS(status));
  DCHECK_NOT_NULL(normalizer);
  uint32_t normalized_prefix_length =
      normalizer->spanQuickCheckYes(input, status);
  // Quick return if the input is already normalized.
  if (length == normalized_prefix_length) return string;
  icu::UnicodeString unnormalized =
      input.tempSubString(normalized_prefix_length);
  // Read-only alias of the normalized prefix.
  result.setTo(false, input.getBuffer(), normalized_prefix_length);
  // copy-on-write; normalize the suffix and append to |result|.
  normalizer->normalizeSecondAndAppend(result, unnormalized, status);

  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }

  return Intl::ToString(isolate, result);
}

// ICUTimezoneCache calls out to ICU for TimezoneCache
// functionality in a straightforward way.
class ICUTimezoneCache : public base::TimezoneCache {
 public:
  ICUTimezoneCache() : timezone_(nullptr) { Clear(TimeZoneDetection::kSkip); }

  ~ICUTimezoneCache() override { Clear(TimeZoneDetection::kSkip); }

  const char* LocalTimezone(double time_ms) override;

  double DaylightSavingsOffset(double time_ms) override;

  double LocalTimeOffset(double time_ms, bool is_utc) override;

  void Clear(TimeZoneDetection time_zone_detection) override;

 private:
  icu::TimeZone* GetTimeZone();

  bool GetOffsets(double time_ms, bool is_utc, int32_t* raw_offset,
                  int32_t* dst_offset);

  icu::TimeZone* timezone_;

  std::string timezone_name_;
  std::string dst_timezone_name_;
};

const char* ICUTimezoneCache::LocalTimezone(double time_ms) {
  bool is_dst = DaylightSavingsOffset(time_ms) != 0;
  std::string* name = is_dst ? &dst_timezone_name_ : &timezone_name_;
  if (name->empty()) {
    icu::UnicodeString result;
    GetTimeZone()->getDisplayName(is_dst, icu::TimeZone::LONG, result);
    result += '\0';

    icu::StringByteSink<std::string> byte_sink(name);
    result.toUTF8(byte_sink);
  }
  DCHECK(!name->empty());
  return name->c_str();
}

icu::TimeZone* ICUTimezoneCache::GetTimeZone() {
  if (timezone_ == nullptr) {
    timezone_ = icu::TimeZone::createDefault();
  }
  return timezone_;
}

bool ICUTimezoneCache::GetOffsets(double time_ms, bool is_utc,
                                  int32_t* raw_offset, int32_t* dst_offset) {
  UErrorCode status = U_ZERO_ERROR;
  if (is_utc) {
    GetTimeZone()->getOffset(time_ms, false, *raw_offset, *dst_offset, status);
  } else {
    // Note that casting TimeZone to BasicTimeZone is safe because we know that
    // icu::TimeZone used here is a BasicTimeZone.
    static_cast<const icu::BasicTimeZone*>(GetTimeZone())
        ->getOffsetFromLocal(time_ms, UCAL_TZ_LOCAL_FORMER,
                             UCAL_TZ_LOCAL_FORMER, *raw_offset, *dst_offset,
                             status);
  }

  return U_SUCCESS(status);
}

double ICUTimezoneCache::DaylightSavingsOffset(double time_ms) {
  int32_t raw_offset, dst_offset;
  if (!GetOffsets(time_ms, true, &raw_offset, &dst_offset)) return 0;
  return dst_offset;
}

double ICUTimezoneCache::LocalTimeOffset(double time_ms, bool is_utc) {
  int32_t raw_offset, dst_offset;
  if (!GetOffsets(time_ms, is_utc, &raw_offset, &dst_offset)) return 0;
  return raw_offset + dst_offset;
}

void ICUTimezoneCache::Clear(TimeZoneDetection time_zone_detection) {
  delete timezone_;
  timezone_ = nullptr;
  timezone_name_.clear();
  dst_timezone_name_.clear();
  if (time_zone_detection == TimeZoneDetection::kRedetect) {
    icu::TimeZone::adoptDefault(icu::TimeZone::detectHostTimeZone());
  }
}

base::TimezoneCache* Intl::CreateTimeZoneCache() {
  return v8_flags.icu_timezone_data ? new ICUTimezoneCache()
                                    : base::OS::CreateTimezoneCache();
}

Maybe<Intl::MatcherOption> Intl::GetLocaleMatcher(Isolate* isolate,
                                                  Handle<JSReceiver> options,
                                                  const char* method_name) {
  return GetStringOption<Intl::MatcherOption>(
      isolate, options, "localeMatcher", method_name, {"best fit", "lookup"},
      {Intl::MatcherOption::kBestFit, Intl::MatcherOption::kLookup},
      Intl::MatcherOption::kBestFit);
}

Maybe<bool> Intl::GetNumberingSystem(Isolate* isolate,
                                     Handle<JSReceiver> options,
                                     const char* method_name,
                                     std::unique_ptr<char[]>* result) {
  const std::vector<const char*> empty_values = {};
  Maybe<bool> maybe = GetStringOption(isolate, options, "numberingSystem",
                                      empty_values, method_name, result);
  MAYBE_RETURN(maybe, Nothing<bool>());
  if (maybe.FromJust() && *result != nullptr) {
    if (!IsWellFormedNumberingSystem(result->get())) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(
              MessageTemplate::kInvalid,
              isolate->factory()->numberingSystem_string(),
              isolate->factory()->NewStringFromAsciiChecked(result->get())),
          Nothing<bool>());
    }
    return Just(true);
  }
  return Just(false);
}

const std::set<std::string>& Intl::GetAvailableLocales() {
  static base::LazyInstance<Intl::AvailableLocales<>>::type available_locales =
      LAZY_INSTANCE_INITIALIZER;
  return available_locales.Pointer()->Get();
}

namespace {

struct CheckCalendar {
  static const char* key() { return "calendar"; }
  static const char* path() { return nullptr; }
};

}  // namespace

const std::set<std::string>& Intl::GetAvailableLocalesForDateFormat() {
  static base::LazyInstance<Intl::AvailableLocales<CheckCalendar>>::type
      available_locales = LAZY_INSTANCE_INITIALIZER;
  return available_locales.Pointer()->Get();
}

constexpr uint16_t kInfinityChar = 0x221e;

Handle<String> Intl::NumberFieldToType(Isolate* isolate,
                                       const NumberFormatSpan& part,
                                       const icu::UnicodeString& text,
                                       bool is_nan) {
  switch (static_cast<UNumberFormatFields>(part.field_id)) {
    case UNUM_INTEGER_FIELD:
      if (is_nan) return isolate->factory()->nan_string();
      if (text.charAt(part.begin_pos) == kInfinityChar ||
          // en-US-POSIX output "INF" for Infinity
          (part.end_pos - part.begin_pos == 3 &&
           text.tempSubString(part.begin_pos, 3) == "INF")) {
        return isolate->factory()->infinity_string();
      }
      return isolate->factory()->integer_string();
    case UNUM_FRACTION_FIELD:
      return isolate->factory()->fraction_string();
    case UNUM_DECIMAL_SEPARATOR_FIELD:
      return isolate->factory()->decimal_string();
    case UNUM_GROUPING_SEPARATOR_FIELD:
      return isolate->factory()->group_string();
    case UNUM_CURRENCY_FIELD:
      return isolate->factory()->currency_string();
    case UNUM_PERCENT_FIELD:
      return isolate->factory()->percentSign_string();
    case UNUM_SIGN_FIELD:
      return (text.charAt(part.begin_pos) == '+')
                 ? isolate->factory()->plusSign_string()
                 : isolate->factory()->minusSign_string();
    case UNUM_EXPONENT_SYMBOL_FIELD:
      return isolate->factory()->exponentSeparator_string();

    case UNUM_EXPONENT_SIGN_FIELD:
      return isolate->factory()->exponentMinusSign_string();

    case UNUM_EXPONENT_FIELD:
      return isolate->factory()->exponentInteger_string();

    case UNUM_PERMILL_FIELD:
      // We're not creating any permill formatter, and it's not even clear how
      // that would be possible with the ICU API.
      UNREACHABLE();

    case UNUM_COMPACT_FIELD:
      return isolate->factory()->compact_string();
    case UNUM_MEASURE_UNIT_FIELD:
      return isolate->factory()->unit_string();

    case UNUM_APPROXIMATELY_SIGN_FIELD:
      return isolate->factory()->approximatelySign_string();

    default:
      UNREACHABLE();
  }
}

// A helper function to convert the FormattedValue for several Intl objects.
MaybeHandle<String> Intl::FormattedToString(
    Isolate* isolate, const icu::FormattedValue& formatted) {
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString result = formatted.toString(status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  return Intl::ToString(isolate, result);
}

MaybeHandle<JSArray> Intl::ToJSArray(
    Isolate* isolate, const char* unicode_key,
    icu::StringEnumeration* enumeration,
    const std::function<bool(const char*)>& removes, bool sort) {
  UErrorCode status = U_ZERO_ERROR;
  std::vector<std::string> array;
  for (const char* item = enumeration->next(nullptr, status);
       U_SUCCESS(status) && item != nullptr;
       item = enumeration->next(nullptr, status)) {
    if (unicode_key != nullptr) {
      item = uloc_toUnicodeLocaleType(unicode_key, item);
    }
    if (removes == nullptr || !(removes)(item)) {
      array.push_back(item);
    }
  }

  if (sort) {
    std::sort(array.begin(), array.end());
  }
  return VectorToJSArray(isolate, array);
}

bool Intl::RemoveCollation(const char* collation) {
  return strcmp("standard", collation) == 0 || strcmp("search", collation) == 0;
}

// See the list in ecma402 #sec-issanctionedsimpleunitidentifier
std::set<std::string> Intl::SanctionedSimpleUnits() {
  return std::set<std::string>(
      {"acre",        "bit",         "byte",        "celsius",
       "centimeter",  "day",         "degree",      "fahrenheit",
       "fluid-ounce", "foot",        "gallon",      "gigabit",
       "gigabyte",    "gram",        "hectare",     "hour",
       "inch",        "kilobit",     "kilobyte",    "kilogram",
       "kilometer",   "liter",       "megabit",     "megabyte",
       "meter",       "microsecond", "mile",        "mile-scandinavian",
       "millimeter",  "milliliter",  "millisecond", "minute",
       "month",       "nanosecond",  "ounce",       "percent",
       "petabyte",    "pound",       "second",      "stone",
       "terabit",     "terabyte",    "week",        "yard",
       "year"});
}

// ecma-402/#sec-isvalidtimezonename

namespace {
bool IsUnicodeStringValidTimeZoneName(const icu::UnicodeString& id) {
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString canonical;
  icu::TimeZone::getCanonicalID(id, canonical, status);
  return U_SUCCESS(status) &&
         canonical != icu::UnicodeString("Etc/Unknown", -1, US_INV);
}
}  // namespace

MaybeHandle<String> Intl::CanonicalizeTimeZoneName(
    Isolate* isolate, DirectHandle<String> identifier) {
  UErrorCode status = U_ZERO_ERROR;
  std::string time_zone =
      JSDateTimeFormat::CanonicalizeTimeZoneID(identifier->ToCString().get());
  icu::UnicodeString time_zone_ustring =
      icu::UnicodeString(time_zone.c_str(), -1, US_INV);
  icu::UnicodeString canonical;
  icu::TimeZone::getCanonicalID(time_zone_ustring, canonical, status);
  CHECK(U_SUCCESS(status));

  return JSDateTimeFormat::TimeZoneIdToString(isolate, canonical);
}

bool Intl::IsValidTimeZoneName(Isolate* isolate, DirectHandle<String> id) {
  std::string time_zone =
      JSDateTimeFormat::CanonicalizeTimeZoneID(id->ToCString().get());
  icu::UnicodeString time_zone_ustring =
      icu::UnicodeString(time_zone.c_str(), -1, US_INV);
  return IsUnicodeStringValidTimeZoneName(time_zone_ustring);
}

bool Intl::IsValidTimeZoneName(const icu::TimeZone& tz) {
  icu::UnicodeString id;
  tz.getID(id);
  return IsUnicodeStringValidTimeZoneName(id);
}

// Function to support Temporal
std::string Intl::TimeZoneIdFromIndex(int32_t index) {
  if (index == JSTemporalTimeZone::kUTCTimeZoneIndex) {
    return "UTC";
  }
  std::unique_ptr<icu::StringEnumeration> enumeration(
      icu::TimeZone::createEnumeration());
  int32_t curr = 0;
  const char* id;

  UErrorCode status = U_ZERO_ERROR;
  while (U_SUCCESS(status) && curr < index &&
         ((id = enumeration->next(nullptr, status)) != nullptr)) {
    CHECK(U_SUCCESS(status));
    curr++;
  }
  CHECK(U_SUCCESS(status));
  CHECK(id != nullptr);
  return id;
}

int32_t Intl::GetTimeZoneIndex(Isolate* isolate,
                               DirectHandle<String> identifier) {
  if (identifier->Equals(*isolate->factory()->UTC_string())) {
    return 0;
  }

  std::string identifier_str(identifier->ToCString().get());
  std::unique_ptr<icu::TimeZone> tz(
      icu::TimeZone::createTimeZone(identifier_str.c_str()));
  if (!IsValidTimeZoneName(*tz)) {
    return -1;
  }

  std::unique_ptr<icu::StringEnumeration> enumeration(
      icu::TimeZone::createEnumeration());
  int32_t curr = 0;
  const char* id;

  UErrorCode status = U_ZERO_ERROR;
  while (U_SUCCESS(status) &&
         (id = enumeration->next(nullptr, status)) != nullptr) {
    curr++;
    if (identifier_str == id) {
      return curr;
    }
  }
  CHECK(U_SUCCESS(status));
  // We should not reach here, the !IsValidTimeZoneName should return earlier
  UNREACHABLE();
}

Intl::FormatRangeSourceTracker::FormatRangeSourceTracker() {
  start_[0] = start_[1] = limit_[0] = limit_[1] = 0;
}

void Intl::FormatRangeSourceTracker::Add(int32_t field, int32_t start,
                                         int32_t limit) {
  DCHECK_LT(field, 2);
  start_[field] = start;
  limit_[field] = limit;
}

Intl::FormatRangeSource Intl::FormatRangeSourceTracker::GetSource(
    int32_t start, int32_t limit) const {
  FormatRangeSource source = FormatRangeSource::kShared;
  if (FieldContains(0, start, limit)) {
    source = FormatRangeSource::kStartRange;
  } else if (FieldContains(1, start, limit)) {
    source = FormatRangeSource::kEndRange;
  }
  return source;
}

bool Intl::FormatRangeSourceTracker::FieldContains(int32_t field, int32_t start,
                                                   int32_t limit) const {
  DCHECK_LT(field, 2);
  return (start_[field] <= start) && (start <= limit_[field]) &&
         (start_[field] <= limit) && (limit <= limit_[field]);
}

Handle<String> Intl::SourceString(Isolate* isolate, FormatRangeSource source) {
  switch (source) {
    case FormatRangeSource::kShared:
      return ReadOnlyRoots(isolate).shared_string_handle();
    case FormatRangeSource::kStartRange:
      return ReadOnlyRoots(isolate).startRange_string_handle();
    case FormatRangeSource::kEndRange:
      return ReadOnlyRoots(isolate).endRange_string_handle();
  }
}

Handle<String> Intl::DefaultTimeZone(Isolate* isolate) {
  icu::UnicodeString id;
  {
    std::unique_ptr<icu::TimeZone> tz(icu::TimeZone::createDefault());
    tz->getID(id);
  }
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString canonical;
  icu::TimeZone::getCanonicalID(id, canonical, status);
  DCHECK(U_SUCCESS(status));
  return JSDateTimeFormat::TimeZoneIdToString(isolate, canonical)
      .ToHandleChecked();
}

namespace {

const icu::BasicTimeZone* CreateBasicTimeZoneFromIndex(
    int32_t time_zone_index) {
  DCHECK_NE(time_zone_index, 0);
  return static_cast<const icu::BasicTimeZone*>(
      icu::TimeZone::createTimeZone(icu::UnicodeString(
          Intl::TimeZoneIdFromIndex(time_zone_index).c_str(), -1, US_INV)));
}

// ICU only support TimeZone information in millisecond but Temporal require
// nanosecond. For most of the case, we find an approximate millisecond by
// floor to the millisecond just past the nanosecond_epoch. For negative epoch
// value, the BigInt Divide will floor closer to zero so we need to minus 1 if
// the remainder is not zero. For the case of finding previous transition, we
// need to ceil to the millisecond in the near future of the nanosecond_epoch.
enum class Direction { kPast, kFuture };
int64_t ApproximateMillisecondEpoch(Isolate* isolate,
                                    Handle<BigInt> nanosecond_epoch,
                                    Direction direction = Direction::kPast) {
  DirectHandle<BigInt> one_million = BigInt::FromUint64(isolate, 1000000);
  int64_t ms = BigInt::Divide(isolate, nanosecond_epoch, one_million)
                   .ToHandleChecked()
                   ->AsInt64();
  DirectHandle<BigInt> remainder =
      BigInt::Remainder(isolate, nanosecond_epoch, one_million)
          .ToHandleChecked();
  // If the nanosecond_epoch is not on the exact millisecond
  if (remainder->ToBoolean()) {
    if (direction == Direction::kPast) {
      if (remainder->IsNegative()) {
        // If the remaninder is negative, we know we have an negative epoch
        // We need to decrease one millisecond.
        // Move to the previous millisecond
        ms -= 1;
      }
    } else {
      if (!remainder->IsNegative()) {
        // Move to the future millisecond
        ms += 1;
      }
    }
  }
  return ms;
}

// Helper function to convert the milliseconds in int64_t
// to a BigInt in nanoseconds.
Handle<BigInt> MillisecondToNanosecond(Isolate* isolate, int64_t ms) {
  return BigInt::Multiply(isolate, BigInt::FromInt64(isolate, ms),
                          BigInt::FromUint64(isolate, 1000000))
      .ToHandleChecked();
}

}  // namespace

Handle<Object> Intl::GetTimeZoneOffsetTransitionNanoseconds(
    Isolate* isolate, int32_t time_zone_index, Handle<BigInt> nanosecond_epoch,
    Intl::Transition transition) {
  std::unique_ptr<const icu::BasicTimeZone> basic_time_zone(
      CreateBasicTimeZoneFromIndex(time_zone_index));

  icu::TimeZoneTransition icu_transition;
  UBool has_transition;
  switch (transition) {
    case Intl::Transition::kNext:
      has_transition = basic_time_zone->getNextTransition(
          ApproximateMillisecondEpoch(isolate, nanosecond_epoch), false,
          icu_transition);
      break;
    case Intl::Transition::kPrevious:
      has_transition = basic_time_zone->getPreviousTransition(
          ApproximateMillisecondEpoch(isolate, nanosecond_epoch,
                                      Direction::kFuture),
          false, icu_transition);
      break;
  }

  if (!has_transition) {
    return isolate->factory()->null_value();
  }
  // #sec-temporal-getianatimezonenexttransition and
  // #sec-temporal-getianatimezoneprevioustransition states:
  // "The operation returns null if no such transition exists for which t ≤
  // ℤ(nsMaxInstant)." and "The operation returns null if no such transition
  // exists for which t ≥ ℤ(nsMinInstant)."
  //
  // nsMinInstant = -nsMaxInstant = -8.64 × 10^21 => msMinInstant = -8.64 x
  // 10^15
  constexpr int64_t kMsMinInstant = -8.64e15;
  // nsMaxInstant = 10^8 × nsPerDay = 8.64 × 10^21 => msMaxInstant = 8.64 x
  // 10^15
  constexpr int64_t kMsMaxInstant = 8.64e15;
  int64_t time_ms = static_cast<int64_t>(icu_transition.getTime());
  if (time_ms < kMsMinInstant || time_ms > kMsMaxInstant) {
    return isolate->factory()->null_value();
  }
  return MillisecondToNanosecond(isolate, time_ms);
}

std::vector<Handle<BigInt>> Intl::GetTimeZonePossibleOffsetNanoseconds(
    Isolate* isolate, int32_t time_zone_index,
    Handle<BigInt> nanosecond_epoch) {
  std::unique_ptr<const icu::BasicTimeZone> basic_time_zone(
      CreateBasicTimeZoneFromIndex(time_zone_index));
  int64_t time_ms = ApproximateMillisecondEpoch(isolate, nanosecond_epoch);
  int32_t raw_offset;
  int32_t dst_offset;
  UErrorCode status = U_ZERO_ERROR;
  basic_time_zone->getOffsetFromLocal(time_ms, UCAL_TZ_LOCAL_FORMER,
                                      UCAL_TZ_LOCAL_FORMER, raw_offset,
                                      dst_offset, status);
  DCHECK(U_SUCCESS(status));
  // offset for time_ms interpretted as before a time zone
  // transition
  int64_t offset_former = raw_offset + dst_offset;

  basic_time_zone->getOffsetFromLocal(time_ms, UCAL_TZ_LOCAL_LATTER,
                                      UCAL_TZ_LOCAL_LATTER, raw_offset,
                                      dst_offset, status);
  DCHECK(U_SUCCESS(status));
  // offset for time_ms interpretted as after a time zone
  // transition
  int64_t offset_latter = raw_offset + dst_offset;

  std::vector<Handle<BigInt>> result;
  if (offset_former == offset_latter) {
    // For most of the time, when either interpretation are the same, we are not
    // in a moment of offset transition based on rule changing: Just return that
    // value.
    result.push_back(MillisecondToNanosecond(isolate, offset_former));
  } else if (offset_former > offset_latter) {
    // When the input represents a local time repeating multiple times at a
    // negative time zone transition (e.g. when the daylight saving time ends
    // or the time zone offset is decreased due to a time zone rule change).
    result.push_back(MillisecondToNanosecond(isolate, offset_former));
    result.push_back(MillisecondToNanosecond(isolate, offset_latter));
  } else {
    // If the offset after the transition is greater than the offset before the
    // transition, that mean it is in the moment the time "skip" an hour, or two
    // (or six in a Time Zone in south pole) in that case there are no possible
    // Time Zone offset for that moment and nothing will be added to the result.
  }
  return result;
}

int64_t Intl::GetTimeZoneOffsetNanoseconds(Isolate* isolate,
                                           int32_t time_zone_index,
                                           Handle<BigInt> nanosecond_epoch) {
  std::unique_ptr<const icu::BasicTimeZone> basic_time_zone(
      CreateBasicTimeZoneFromIndex(time_zone_index));
  int64_t time_ms = ApproximateMillisecondEpoch(isolate, nanosecond_epoch);
  int32_t raw_offset;
  int32_t dst_offset;
  UErrorCode status = U_ZERO_ERROR;
  basic_time_zone->getOffset(time_ms, false, raw_offset, dst_offset, status);
  DCHECK(U_SUCCESS(status));
  // Turn ms into ns
  return static_cast<int64_t>(raw_offset + dst_offset) * 1000000;
}

}  // namespace v8::internal
```