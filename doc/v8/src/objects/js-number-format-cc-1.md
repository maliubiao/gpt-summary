Response:
My thinking process to analyze the provided V8 C++ code snippet goes like this:

1. **Identify the Core Purpose:**  The file name `js-number-format.cc` strongly suggests this code deals with the implementation of the JavaScript `Intl.NumberFormat` object within the V8 JavaScript engine. The comments at the beginning confirming the presence of attributes defined by ECMA-402 further solidify this.

2. **Break Down the Code into Logical Blocks:** I scan the code for function definitions and key logic sections. I notice:
    * A function setting properties on an `options` object based on a `skeleton` string.
    * A function for "unwrapping" a `JSNumberFormat` object.
    * A major `New` function that appears to be the constructor or factory for `JSNumberFormat` instances.
    * Functions for formatting numbers (`FormatDecimalString`, `IcuFormatNumber`, `FormatNumeric`, `FormatRange`).
    * A utility function for trimming whitespace.

3. **Analyze the `SetOptionsFromSkeleton` Function:**
    * **Input:** Takes an `Isolate`, an `options` object (likely a JavaScript object), and a `skeleton` string.
    * **Functionality:**  It parses the `skeleton` string to extract formatting preferences (like locale, numbering system, style, currency, unit, digit constraints, grouping, notation, sign display, and rounding options). It then sets these preferences as properties on the `options` JavaScript object.
    * **Keywords:**  Look for keywords in the code that map to `Intl.NumberFormat` options (e.g., "locale", "numberingSystem", "style", "currencyDisplay", etc.). The initial comment block is invaluable here.
    * **Output:**  Modifies the `options` object in place and returns it.

4. **Analyze the `UnwrapNumberFormat` Function:**
    * **Purpose:** This function checks if a given JavaScript object is a valid `Intl.NumberFormat` instance and returns it. It seems to be used for internal V8 checks.
    * **Error Handling:**  Note the `TypeError` that's thrown if the object isn't a `JSNumberFormat`.

5. **Analyze the `New` Function (The Constructor/Factory):** This is the most complex part.
    * **Purpose:** This is where a new `Intl.NumberFormat` object is created and initialized.
    * **Steps (following the numbered comments):**
        * **Locale Handling:** Canonicalizes and resolves the requested locales.
        * **Options Processing:** Coerces the `options` argument to an object and extracts relevant options like `localeMatcher` and `numberingSystem`.
        * **Style and Unit Options:** Handles the `style`, `currency`, and `unit` options, including validation.
        * **Digit Options:** Processes options related to minimum/maximum integer/fraction digits and significant digits.
        * **Notation and Grouping:** Handles the `notation` and `useGrouping` options.
        * **Sign Display:** Processes the `signDisplay` option.
        * **ICU Integration:**  Creates an `icu::number::LocalizedNumberFormatter` based on the resolved options. This highlights the reliance on the ICU library for the actual formatting logic.
        * **Object Creation:**  Allocates the `JSNumberFormat` object and stores the configured formatter.
    * **Key Observations:** This function heavily uses the `Intl` namespace (internal V8 utilities for internationalization) and interacts with ICU. The numbered comments directly correspond to steps in the ECMA-402 specification.

6. **Analyze the Formatting Functions:**
    * **`FormatDecimalString`:**  Formats a number represented as a string.
    * **`IcuFormatNumber`:**  The core formatting function that handles both numbers and BigInts, leveraging the ICU formatter. It also deals with string inputs.
    * **`FormatNumeric`:** A higher-level formatting function that checks the input type and calls the appropriate formatting function.
    * **`FormatRange`:** Formats a range of numbers.

7. **Analyze the `TrimWhiteSpaceOrLineTerminator` Function:** A simple utility for removing leading/trailing whitespace.

8. **Address the Specific Questions:**

    * **Functionality:** Summarize the identified core purposes of the code.
    * **Torque:** Explicitly state that the file is C++ (`.cc`) and not Torque (`.tq`).
    * **JavaScript Relation:** Explain how the C++ code implements the JavaScript `Intl.NumberFormat` API. Provide a simple JavaScript example demonstrating its usage.
    * **Code Logic/Assumptions:** For the `SetOptionsFromSkeleton` and `New` functions, deduce assumptions about the input `skeleton` and `options` and describe the expected output (modification of the `options` object or creation of a `JSNumberFormat` instance).
    * **Common Errors:** Think about common mistakes users make with `Intl.NumberFormat` (e.g., providing an invalid currency code, forgetting the `currency` option when `style` is "currency").
    * **Summarization (Part 2):** Focus on the core responsibilities of this code *within the broader context of `Intl.NumberFormat` implementation*. Since this is part 2, it likely deals with the *initialization* and *option processing* stages.

9. **Refine and Organize:** Structure the analysis clearly with headings and bullet points. Use precise language and avoid jargon where possible. Ensure the JavaScript examples are simple and illustrative.

By following these steps, I can systematically dissect the code, understand its purpose, and answer the specific questions posed in the prompt. The key is to identify the high-level goals, break down the code into manageable parts, and connect the C++ implementation to the corresponding JavaScript API.
这是目录为 `v8/src/objects/js-number-format.cc` 的一个 V8 源代码文件的第二部分，根据您提供的代码片段，我们可以归纳一下它的功能：

**主要功能：配置和初始化 `Intl.NumberFormat` 对象的内部状态**

这部分代码主要负责根据用户提供的 `locales` 和 `options` 参数，以及内部的 `skeleton` 字符串，来配置和初始化 `Intl.NumberFormat` 对象在 V8 引擎中的表示 (`JSNumberFormat`)。 具体来说，它做了以下几件事：

1. **从 Skeleton 字符串中提取格式化信息：** `SetOptionsFromSkeleton` 函数负责解析一个 `skeleton` 字符串（例如 "currency-EUR"），从中提取出诸如货币类型、显示方式、符号等信息，并将这些信息设置到 `options` JavaScript 对象中。这个 `skeleton` 字符串可能是内部预定义的或者根据某些规则生成的。

2. **创建和初始化 `JSNumberFormat` 对象 (在 `New` 函数中):**
   - **处理 Locales：**  `New` 函数首先处理传入的 `locales` 参数，进行规范化和查找，确定最终使用的 locale。
   - **处理 Options：**  它将传入的 `options_obj` 转换为 JavaScript 对象，并从中提取各种格式化选项，例如 `style`（decimal, percent, currency, unit）、`currency`、`currencyDisplay`、`unit`、`unitDisplay`、数字位数、分组、notation（standard, scientific, engineering, compact）、signDisplay、roundingIncrement 等。
   - **验证和转换选项：** 对某些选项进行验证（例如 `currency` 必须是合法的货币代码，`unit` 必须是合法的 unit identifier）。并将 JavaScript 的选项值转换为 V8 内部使用的枚举或字符串。
   - **与 ICU 库交互：**  它使用 ICU (International Components for Unicode) 库来处理国际化相关的逻辑。根据解析出的选项，配置 ICU 的 `UnlocalizedNumberFormatter` 和 `LocalizedNumberFormatter` 对象，这些对象负责实际的数字格式化工作。
   - **设置内部属性：** 将解析出的 locale、配置好的 ICU formatter 等信息设置到新创建的 `JSNumberFormat` 对象的内部属性中。

3. **提供 `UnwrapNumberFormat` 函数：**  这个函数用于检查一个 JavaScript 对象是否是 `JSNumberFormat` 的实例，并在类型不匹配时抛出 `TypeError`。这通常用于 V8 内部确保操作的目标是正确的 `Intl.NumberFormat` 对象。

**与 JavaScript 的关系 (举例说明):**

这段 C++ 代码实现了 JavaScript 中 `Intl.NumberFormat` 构造函数的底层逻辑。当你创建一个 `Intl.NumberFormat` 对象时，V8 引擎会调用这段 C++ 代码来完成对象的初始化。

```javascript
// JavaScript 示例
const formatter = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
  currencyDisplay: 'symbol'
});

const formattedNumber = formatter.format(1234.56);
console.log(formattedNumber); // 输出 "$1,234.56"
```

在这个例子中，当你执行 `new Intl.NumberFormat('en-US', { ... })` 时，V8 会调用 `v8/src/objects/js-number-format.cc` 中的 `JSNumberFormat::New` 函数，传入 'en-US' 作为 `locales`，`{ style: 'currency', currency: 'USD', currencyDisplay: 'symbol' }` 作为 `options_obj`。C++ 代码会解析这些参数，配置 ICU formatter，并将相关信息存储在创建的 `JSNumberFormat` 对象中。后续调用 `formatter.format(1234.56)` 时，会使用这个配置好的 formatter 来完成实际的格式化。

**代码逻辑推理 (假设输入与输出):**

假设 `skeleton` 输入为 `"currency-EUR-narrowSymbol"`：

* **假设输入:**
    * `isolate`: 当前 V8 引擎的 Isolate 对象。
    * `options`: 一个空的 JavaScript 对象。
    * `skeleton`: 字符串 `"currency-EUR-narrowSymbol"`。

* **代码逻辑推理:** `SetOptionsFromSkeleton` 函数会解析 `skeleton` 字符串：
    * 识别出 `currency` 为 "EUR"。
    * 识别出 `currencyDisplay` 的类型是 "narrowSymbol"。
    * 将这些信息添加到 `options` 对象中。

* **预期输出:** `options` 对象会被修改为包含以下属性（部分）：
    * `locale`: (可能从全局或上下文中获取，例如 "en-US")
    * `numberingSystem`: (可能从 locale 中推断，例如 "latn")
    * `style`: "currency"
    * `currency`: "EUR"
    * `currencyDisplay`: "narrowSymbol"
    * ...其他默认或从 skeleton 中推断出的属性。

**用户常见的编程错误 (举例说明):**

1. **`style` 为 `currency` 但未提供 `currency`:**

   ```javascript
   // 错误示例
   const formatter = new Intl.NumberFormat('en-US', { style: 'currency' });
   // 会抛出 TypeError，因为缺少 currency 选项
   ```

   这段 C++ 代码的 `New` 函数中会检查这种情况，如果 `style` 是 "currency" 但 `currency` 未定义，则会抛出一个 `TypeError`。

2. **提供无效的 `currency` 代码:**

   ```javascript
   // 错误示例
   const formatter = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'XXX' });
   // 会抛出 RangeError，因为 "XXX" 不是有效的货币代码
   ```

   `New` 函数会调用 `IsWellFormedCurrencyCode` 来验证货币代码的有效性，无效的代码会导致 `RangeError`。

**功能归纳 (第 2 部分):**

这部分 `v8/src/objects/js-number-format.cc` 代码的主要功能集中在 **`Intl.NumberFormat` 对象的创建和初始化阶段**。它负责：

* **解析和提取格式化选项：** 从用户提供的参数和内部的 skeleton 字符串中提取出各种格式化偏好。
* **验证选项的有效性：** 确保用户提供的选项值符合规范。
* **配置 ICU 库：**  根据提取出的选项配置 ICU 的 formatter 对象，ICU 负责实际的国际化数字格式化工作。
* **创建和设置 `JSNumberFormat` 对象的内部状态：**  将解析出的信息存储到 V8 内部的 `JSNumberFormat` 对象中，为后续的格式化操作做准备。

简单来说，这部分代码是 `Intl.NumberFormat` 功能的 "配置中心"，确保对象在进行实际的数字格式化之前，其内部状态是正确且符合用户需求的。

### 提示词
```
这是目录为v8/src/objects/js-number-format.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-number-format.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
"currency"
  //    [[CurrencyDisplay]]             "currencyDisplay"
  //    [[CurrencySign]]                "currencySign"
  //    [[Unit]]                        "unit"
  //    [[UnitDisplay]]                 "unitDisplay"
  //    [[MinimumIntegerDigits]]        "minimumIntegerDigits"
  //    [[MinimumFractionDigits]]       "minimumFractionDigits"
  //    [[MaximumFractionDigits]]       "maximumFractionDigits"
  //    [[MinimumSignificantDigits]]    "minimumSignificantDigits"
  //    [[MaximumSignificantDigits]]    "maximumSignificantDigits"
  //    [[UseGrouping]]                 "useGrouping"
  //    [[Notation]]                    "notation"
  //    [[CompactDisplay]]              "compactDisplay"
  //    [[SignDisplay]]                 "signDisplay"
  //    [[RoundingIncrement]]           "roundingIncrement"
  //    [[RoundingMode]]                "roundingMode"
  //    [[ComputedRoundingPriority]]    "roundingPriority"
  //    [[TrailingZeroDisplay]]         "trailingZeroDisplay"

  CHECK(JSReceiver::CreateDataProperty(isolate, options,
                                       factory->locale_string(), locale,
                                       Just(kDontThrow))
            .FromJust());
  Handle<String> numberingSystem_string;
  CHECK(Intl::ToString(isolate, numberingSystem_ustr)
            .ToHandle(&numberingSystem_string));
  CHECK(JSReceiver::CreateDataProperty(isolate, options,
                                       factory->numberingSystem_string(),
                                       numberingSystem_string, Just(kDontThrow))
            .FromJust());
  Style style = StyleFromSkeleton(skeleton);
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->style_string(),
            StyleAsString(isolate, style), Just(kDontThrow))
            .FromJust());
  const icu::UnicodeString currency_ustr = CurrencyFromSkeleton(skeleton);
  if (!currency_ustr.isEmpty()) {
    Handle<String> currency_string;
    CHECK(Intl::ToString(isolate, currency_ustr).ToHandle(&currency_string));
    CHECK(JSReceiver::CreateDataProperty(isolate, options,
                                         factory->currency_string(),
                                         currency_string, Just(kDontThrow))
              .FromJust());

    CHECK(JSReceiver::CreateDataProperty(
              isolate, options, factory->currencyDisplay_string(),
              CurrencyDisplayString(isolate, skeleton), Just(kDontThrow))
              .FromJust());
    CHECK(JSReceiver::CreateDataProperty(
              isolate, options, factory->currencySign_string(),
              CurrencySignString(isolate, skeleton), Just(kDontThrow))
              .FromJust());
  }

  if (style == Style::UNIT) {
    std::string unit = UnitFromSkeleton(skeleton);
    if (!unit.empty()) {
      CHECK(JSReceiver::CreateDataProperty(
                isolate, options, factory->unit_string(),
                isolate->factory()->NewStringFromAsciiChecked(unit.c_str()),
                Just(kDontThrow))
                .FromJust());
    }
    CHECK(JSReceiver::CreateDataProperty(
              isolate, options, factory->unitDisplay_string(),
              UnitDisplayString(isolate, skeleton), Just(kDontThrow))
              .FromJust());
  }

  CHECK(
      JSReceiver::CreateDataProperty(
          isolate, options, factory->minimumIntegerDigits_string(),
          factory->NewNumberFromInt(MinimumIntegerDigitsFromSkeleton(skeleton)),
          Just(kDontThrow))
          .FromJust());

  int32_t mnsd = 0, mxsd = 0, mnfd = 0, mxfd = 0;
  if (FractionDigitsFromSkeleton(skeleton, &mnfd, &mxfd)) {
    CHECK(JSReceiver::CreateDataProperty(
              isolate, options, factory->minimumFractionDigits_string(),
              factory->NewNumberFromInt(mnfd), Just(kDontThrow))
              .FromJust());
    CHECK(JSReceiver::CreateDataProperty(
              isolate, options, factory->maximumFractionDigits_string(),
              factory->NewNumberFromInt(mxfd), Just(kDontThrow))
              .FromJust());
  }
  if (SignificantDigitsFromSkeleton(skeleton, &mnsd, &mxsd)) {
    CHECK(JSReceiver::CreateDataProperty(
              isolate, options, factory->minimumSignificantDigits_string(),
              factory->NewNumberFromInt(mnsd), Just(kDontThrow))
              .FromJust());
    CHECK(JSReceiver::CreateDataProperty(
              isolate, options, factory->maximumSignificantDigits_string(),
              factory->NewNumberFromInt(mxsd), Just(kDontThrow))
              .FromJust());
  }

  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->useGrouping_string(),
            UseGroupingFromSkeleton(isolate, skeleton), Just(kDontThrow))
            .FromJust());

  Notation notation = NotationFromSkeleton(skeleton);
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->notation_string(),
            NotationAsString(isolate, notation), Just(kDontThrow))
            .FromJust());
  // Only output compactDisplay when notation is compact.
  if (notation == Notation::COMPACT) {
    CHECK(JSReceiver::CreateDataProperty(
              isolate, options, factory->compactDisplay_string(),
              CompactDisplayString(isolate, skeleton), Just(kDontThrow))
              .FromJust());
  }
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->signDisplay_string(),
            SignDisplayString(isolate, skeleton), Just(kDontThrow))
            .FromJust());
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->roundingIncrement_string(),
            RoundingIncrement(isolate, skeleton), Just(kDontThrow))
            .FromJust());
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->roundingMode_string(),
            RoundingModeString(isolate, skeleton), Just(kDontThrow))
            .FromJust());
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->roundingPriority_string(),
            RoundingPriorityString(isolate, skeleton), Just(kDontThrow))
            .FromJust());
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->trailingZeroDisplay_string(),
            TrailingZeroDisplayString(isolate, skeleton), Just(kDontThrow))
            .FromJust());
  return options;
}

// ecma402/#sec-unwrapnumberformat
MaybeHandle<JSNumberFormat> JSNumberFormat::UnwrapNumberFormat(
    Isolate* isolate, Handle<JSReceiver> format_holder) {
  // old code copy from NumberFormat::Unwrap that has no spec comment and
  // compiled but fail unit tests.
  DirectHandle<Context> native_context(isolate->context()->native_context(),
                                       isolate);
  Handle<JSFunction> constructor(
      Cast<JSFunction>(native_context->intl_number_format_function()), isolate);
  Handle<Object> object;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, object,
      Intl::LegacyUnwrapReceiver(isolate, format_holder, constructor,
                                 IsJSNumberFormat(*format_holder)));
  // 4. If ... or nf does not have an [[InitializedNumberFormat]] internal slot,
  // then
  if (!IsJSNumberFormat(*object)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kIncompatibleMethodReceiver,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     "UnwrapNumberFormat")));
  }
  // 5. Return nf.
  return Cast<JSNumberFormat>(object);
}

// static
MaybeHandle<JSNumberFormat> JSNumberFormat::New(Isolate* isolate,
                                                DirectHandle<Map> map,
                                                Handle<Object> locales,
                                                Handle<Object> options_obj,
                                                const char* service) {
  Factory* factory = isolate->factory();

  // 1. Let requestedLocales be ? CanonicalizeLocaleList(locales).
  Maybe<std::vector<std::string>> maybe_requested_locales =
      Intl::CanonicalizeLocaleList(isolate, locales);
  MAYBE_RETURN(maybe_requested_locales, Handle<JSNumberFormat>());
  std::vector<std::string> requested_locales =
      maybe_requested_locales.FromJust();

  // 2. Set options to ? CoerceOptionsToObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, CoerceOptionsToObject(isolate, options_obj, service));

  // 3. Let opt be a new Record.
  // 4. Let matcher be ? GetOption(options, "localeMatcher", "string", «
  // "lookup", "best fit" », "best fit").
  // 5. Set opt.[[localeMatcher]] to matcher.
  Maybe<Intl::MatcherOption> maybe_locale_matcher =
      Intl::GetLocaleMatcher(isolate, options, service);
  MAYBE_RETURN(maybe_locale_matcher, MaybeHandle<JSNumberFormat>());
  Intl::MatcherOption matcher = maybe_locale_matcher.FromJust();

  std::unique_ptr<char[]> numbering_system_str = nullptr;
  // 6. Let _numberingSystem_ be ? GetOption(_options_, `"numberingSystem"`,
  //    `"string"`, *undefined*, *undefined*).
  Maybe<bool> maybe_numberingSystem = Intl::GetNumberingSystem(
      isolate, options, service, &numbering_system_str);
  // 7. If _numberingSystem_ is not *undefined*, then
  // 8. If _numberingSystem_ does not match the
  //    `(3*8alphanum) *("-" (3*8alphanum))` sequence, throw a *RangeError*
  //     exception.
  MAYBE_RETURN(maybe_numberingSystem, MaybeHandle<JSNumberFormat>());

  // 9. Let localeData be %NumberFormat%.[[LocaleData]].
  // 10. Let r be ResolveLocale(%NumberFormat%.[[AvailableLocales]],
  // requestedLocales, opt,  %NumberFormat%.[[RelevantExtensionKeys]],
  // localeData).
  std::set<std::string> relevant_extension_keys{"nu"};
  Maybe<Intl::ResolvedLocale> maybe_resolve_locale =
      Intl::ResolveLocale(isolate, JSNumberFormat::GetAvailableLocales(),
                          requested_locales, matcher, relevant_extension_keys);
  if (maybe_resolve_locale.IsNothing()) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  Intl::ResolvedLocale r = maybe_resolve_locale.FromJust();

  icu::Locale icu_locale = r.icu_locale;
  UErrorCode status = U_ZERO_ERROR;
  if (numbering_system_str != nullptr) {
    auto nu_extension_it = r.extensions.find("nu");
    if (nu_extension_it != r.extensions.end() &&
        nu_extension_it->second != numbering_system_str.get()) {
      icu_locale.setUnicodeKeywordValue("nu", nullptr, status);
      DCHECK(U_SUCCESS(status));
    }
  }

  // 9. Set numberFormat.[[Locale]] to r.[[locale]].
  Maybe<std::string> maybe_locale_str = Intl::ToLanguageTag(icu_locale);
  MAYBE_RETURN(maybe_locale_str, MaybeHandle<JSNumberFormat>());
  DirectHandle<String> locale_str =
      isolate->factory()->NewStringFromAsciiChecked(
          maybe_locale_str.FromJust().c_str());

  if (numbering_system_str != nullptr &&
      Intl::IsValidNumberingSystem(numbering_system_str.get())) {
    icu_locale.setUnicodeKeywordValue("nu", numbering_system_str.get(), status);
    DCHECK(U_SUCCESS(status));
  }

  std::string numbering_system = Intl::GetNumberingSystem(icu_locale);

  // 11. Let dataLocale be r.[[dataLocale]].

  icu::number::UnlocalizedNumberFormatter settings =
      icu::number::UnlocalizedNumberFormatter().roundingMode(UNUM_ROUND_HALFUP);

  // For 'latn' numbering system, skip the adoptSymbols which would cause
  // 10.1%-13.7% of regression of JSTests/Intl-NewIntlNumberFormat
  // See crbug/1052751 so we skip calling adoptSymbols and depending on the
  // default instead.
  if (!numbering_system.empty() && numbering_system != "latn") {
    settings = settings.adoptSymbols(icu::NumberingSystem::createInstanceByName(
        numbering_system.c_str(), status));
    DCHECK(U_SUCCESS(status));
  }

  // ==== Start SetNumberFormatUnitOptions ====
  // 3. Let style be ? GetOption(options, "style", "string",  « "decimal",
  // "percent", "currency", "unit" », "decimal").

  Maybe<Style> maybe_style = GetStringOption<Style>(
      isolate, options, "style", service,
      {"decimal", "percent", "currency", "unit"},
      {Style::DECIMAL, Style::PERCENT, Style::CURRENCY, Style::UNIT},
      Style::DECIMAL);
  MAYBE_RETURN(maybe_style, MaybeHandle<JSNumberFormat>());
  Style style = maybe_style.FromJust();

  // 4. Set intlObj.[[Style]] to style.

  // 5. Let currency be ? GetOption(options, "currency", "string", undefined,
  // undefined).
  std::unique_ptr<char[]> currency_cstr;
  const std::vector<const char*> empty_values = {};
  Maybe<bool> found_currency = GetStringOption(
      isolate, options, "currency", empty_values, service, &currency_cstr);
  MAYBE_RETURN(found_currency, MaybeHandle<JSNumberFormat>());

  std::string currency;
  // 6. If currency is not undefined, then
  if (found_currency.FromJust()) {
    DCHECK_NOT_NULL(currency_cstr.get());
    currency = currency_cstr.get();
    // 6. a. If the result of IsWellFormedCurrencyCode(currency) is false,
    // throw a RangeError exception.
    if (!IsWellFormedCurrencyCode(currency)) {
      THROW_NEW_ERROR(
          isolate,
          NewRangeError(MessageTemplate::kInvalid,
                        factory->NewStringFromStaticChars("currency code"),
                        factory->NewStringFromAsciiChecked(currency.c_str())));
    }
  } else {
    // 7. If style is "currency" and currency is undefined, throw a TypeError
    // exception.
    if (style == Style::CURRENCY) {
      THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kCurrencyCode));
    }
  }
  // 8. Let currencyDisplay be ? GetOption(options, "currencyDisplay",
  // "string", « "code",  "symbol", "name", "narrowSymbol" », "symbol").
  Maybe<CurrencyDisplay> maybe_currency_display =
      GetStringOption<CurrencyDisplay>(
          isolate, options, "currencyDisplay", service,
          {"code", "symbol", "name", "narrowSymbol"},
          {CurrencyDisplay::CODE, CurrencyDisplay::SYMBOL,
           CurrencyDisplay::NAME, CurrencyDisplay::NARROW_SYMBOL},
          CurrencyDisplay::SYMBOL);
  MAYBE_RETURN(maybe_currency_display, MaybeHandle<JSNumberFormat>());
  CurrencyDisplay currency_display = maybe_currency_display.FromJust();

  CurrencySign currency_sign = CurrencySign::STANDARD;
  // 9. Let currencySign be ? GetOption(options, "currencySign", "string", «
  // "standard",  "accounting" », "standard").
  Maybe<CurrencySign> maybe_currency_sign = GetStringOption<CurrencySign>(
      isolate, options, "currencySign", service, {"standard", "accounting"},
      {CurrencySign::STANDARD, CurrencySign::ACCOUNTING},
      CurrencySign::STANDARD);
  MAYBE_RETURN(maybe_currency_sign, MaybeHandle<JSNumberFormat>());
  currency_sign = maybe_currency_sign.FromJust();

  // 10. Let unit be ? GetOption(options, "unit", "string", undefined,
  // undefined).
  std::unique_ptr<char[]> unit_cstr;
  Maybe<bool> found_unit = GetStringOption(isolate, options, "unit",
                                           empty_values, service, &unit_cstr);
  MAYBE_RETURN(found_unit, MaybeHandle<JSNumberFormat>());

  std::pair<icu::MeasureUnit, icu::MeasureUnit> unit_pair;
  // 11. If unit is not undefined, then
  if (found_unit.FromJust()) {
    DCHECK_NOT_NULL(unit_cstr.get());
    std::string unit = unit_cstr.get();
    // 11.a If the result of IsWellFormedUnitIdentifier(unit) is false, throw a
    // RangeError exception.
    Maybe<std::pair<icu::MeasureUnit, icu::MeasureUnit>> maybe_wellformed_unit =
        IsWellFormedUnitIdentifier(isolate, unit);
    if (maybe_wellformed_unit.IsNothing()) {
      THROW_NEW_ERROR(
          isolate,
          NewRangeError(MessageTemplate::kInvalidUnit,
                        factory->NewStringFromAsciiChecked(service),
                        factory->NewStringFromAsciiChecked(unit.c_str())));
    }
    unit_pair = maybe_wellformed_unit.FromJust();
  } else {
    // 12. If style is "unit" and unit is undefined, throw a TypeError
    // exception.
    if (style == Style::UNIT) {
      THROW_NEW_ERROR(isolate,
                      NewTypeError(MessageTemplate::kInvalidUnit,
                                   factory->NewStringFromAsciiChecked(service),
                                   factory->empty_string()));
    }
  }

  // 13. Let unitDisplay be ? GetOption(options, "unitDisplay", "string", «
  // "short", "narrow", "long" »,  "short").
  Maybe<UnitDisplay> maybe_unit_display = GetStringOption<UnitDisplay>(
      isolate, options, "unitDisplay", service, {"short", "narrow", "long"},
      {UnitDisplay::SHORT, UnitDisplay::NARROW, UnitDisplay::LONG},
      UnitDisplay::SHORT);
  MAYBE_RETURN(maybe_unit_display, MaybeHandle<JSNumberFormat>());
  UnitDisplay unit_display = maybe_unit_display.FromJust();

  // 14. If style is "currency", then
  icu::UnicodeString currency_ustr;
  if (style == Style::CURRENCY) {
    // 14.a. If currency is undefined, throw a TypeError exception.
    if (!found_currency.FromJust()) {
      THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kCurrencyCode));
    }
    // 14.a. Let currency be the result of converting currency to upper case as
    //    specified in 6.1
    std::transform(currency.begin(), currency.end(), currency.begin(), toupper);
    currency_ustr = currency.c_str();

    // 14.b. Set numberFormat.[[Currency]] to currency.
    if (!currency_ustr.isEmpty()) {
      Handle<String> currency_string;
      ASSIGN_RETURN_ON_EXCEPTION(isolate, currency_string,
                                 Intl::ToString(isolate, currency_ustr));

      settings =
          settings.unit(icu::CurrencyUnit(currency_ustr.getBuffer(), status));
      DCHECK(U_SUCCESS(status));
      // 14.c Set intlObj.[[CurrencyDisplay]] to currencyDisplay.
      // The default unitWidth is SHORT in ICU and that mapped from
      // Symbol so we can skip the setting for optimization.
      if (currency_display != CurrencyDisplay::SYMBOL) {
        settings = settings.unitWidth(ToUNumberUnitWidth(currency_display));
      }
      DCHECK(U_SUCCESS(status));
    }
  }

  // 15. If style is "unit", then
  if (style == Style::UNIT) {
    // Track newer style "unit".
    isolate->CountUsage(v8::Isolate::UseCounterFeature::kNumberFormatStyleUnit);

    icu::MeasureUnit none = icu::MeasureUnit();
    // 13.b Set intlObj.[[Unit]] to unit.
    if (unit_pair.first != AVOID_AMBIGUOUS_OP_WARNING(none)) {
      settings = settings.unit(unit_pair.first);
    }
    if (unit_pair.second != AVOID_AMBIGUOUS_OP_WARNING(none)) {
      settings = settings.perUnit(unit_pair.second);
    }

    // The default unitWidth is SHORT in ICU and that mapped from
    // Symbol so we can skip the setting for optimization.
    if (unit_display != UnitDisplay::SHORT) {
      settings = settings.unitWidth(ToUNumberUnitWidth(unit_display));
    }
  }

  // === End of SetNumberFormatUnitOptions

  if (style == Style::PERCENT) {
    settings = settings.unit(icu::MeasureUnit::getPercent())
                   .scale(icu::number::Scale::powerOfTen(2));
  }

  Notation notation = Notation::STANDARD;
  // xx. Let notation be ? GetOption(options, "notation", "string", «
  // "standard", "scientific",  "engineering", "compact" », "standard").
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, notation,
      GetStringOption<Notation>(
          isolate, options, "notation", service,
          {"standard", "scientific", "engineering", "compact"},
          {Notation::STANDARD, Notation::SCIENTIFIC, Notation::ENGINEERING,
           Notation::COMPACT},
          Notation::STANDARD),
      Handle<JSNumberFormat>());
  // xx. Set numberFormat.[[Notation]] to notation.

  // xx. If style is *"currency"* and *"notation"* is *"standard"*, then
  int mnfd_default, mxfd_default;
  if (style == Style::CURRENCY && notation == Notation::STANDARD) {
    // b. Let cDigits be CurrencyDigits(currency).
    int c_digits = CurrencyDigits(currency_ustr);
    // c. Let mnfdDefault be cDigits.
    // d. Let mxfdDefault be cDigits.
    mnfd_default = c_digits;
    mxfd_default = c_digits;
    // 17. Else,
  } else {
    // a. Let mnfdDefault be 0.
    mnfd_default = 0;
    // b. If style is "percent", then
    if (style == Style::PERCENT) {
      // i. Let mxfdDefault be 0.
      mxfd_default = 0;
    } else {
      // c. Else,
      // i. Let mxfdDefault be 3.
      mxfd_default = 3;
    }
  }

  // 23. Perform ? SetNumberFormatDigitOptions(numberFormat, options,
  // mnfdDefault, mxfdDefault).
  Maybe<Intl::NumberFormatDigitOptions> maybe_digit_options =
      Intl::SetNumberFormatDigitOptions(isolate, options, mnfd_default,
                                        mxfd_default,
                                        notation == Notation::COMPACT, service);
  MAYBE_RETURN(maybe_digit_options, Handle<JSNumberFormat>());
  Intl::NumberFormatDigitOptions digit_options = maybe_digit_options.FromJust();

  // 13. If roundingIncrement is not 1, set mxfdDefault to mnfdDefault.
  if (digit_options.rounding_increment != 1) {
    mxfd_default = mnfd_default;
  }
  // 14. Set intlObj.[[RoundingIncrement]] to roundingIncrement.

  // 15. Set intlObj.[[RoundingMode]] to roundingMode.

  // 16. Set intlObj.[[TrailingZeroDisplay]] to trailingZeroDisplay.
  settings = SetDigitOptionsToFormatter(settings, digit_options);

  // 28. Let compactDisplay be ? GetOption(options, "compactDisplay",
  // "string", « "short", "long" »,  "short").
  Maybe<CompactDisplay> maybe_compact_display = GetStringOption<CompactDisplay>(
      isolate, options, "compactDisplay", service, {"short", "long"},
      {CompactDisplay::SHORT, CompactDisplay::LONG}, CompactDisplay::SHORT);
  MAYBE_RETURN(maybe_compact_display, MaybeHandle<JSNumberFormat>());
  CompactDisplay compact_display = maybe_compact_display.FromJust();

  // The default notation in ICU is Simple, which mapped from STANDARD
  // so we can skip setting it.
  if (notation != Notation::STANDARD) {
    settings = settings.notation(ToICUNotation(notation, compact_display));
  }

  // 28. Let defaultUseGrouping be "auto".
  UseGrouping default_use_grouping = UseGrouping::AUTO;

  // 29. If notation is "compact", then
  if (notation == Notation::COMPACT) {
    // a. Set numberFormat.[[CompactDisplay]] to compactDisplay.
    // Done in above together
    // b. Set defaultUseGrouping to "min2".
    default_use_grouping = UseGrouping::MIN2;
  }

  // 30. Let useGrouping be ? GetStringOrBooleanOption(options, "useGrouping",
  // « "min2", "auto", "always" », "always", false, defaultUseGrouping).
  Maybe<UseGrouping> maybe_use_grouping = GetStringOrBooleanOption<UseGrouping>(
      isolate, options, "useGrouping", service, {"min2", "auto", "always"},
      {UseGrouping::MIN2, UseGrouping::AUTO, UseGrouping::ALWAYS},
      UseGrouping::ALWAYS,    // trueValue
      UseGrouping::OFF,       // falseValue
      default_use_grouping);  // fallbackValue
  MAYBE_RETURN(maybe_use_grouping, MaybeHandle<JSNumberFormat>());
  UseGrouping use_grouping = maybe_use_grouping.FromJust();
  // 31. Set numberFormat.[[UseGrouping]] to useGrouping.
  if (use_grouping != UseGrouping::AUTO) {
    settings = settings.grouping(ToUNumberGroupingStrategy(use_grouping));
  }

  // 32. Let signDisplay be ? GetOption(options, "signDisplay", "string", «
  // "auto", "never", "always",  "exceptZero", "negative" », "auto").
  Maybe<SignDisplay> maybe_sign_display = Nothing<SignDisplay>();
  maybe_sign_display = GetStringOption<SignDisplay>(
      isolate, options, "signDisplay", service,
      {"auto", "never", "always", "exceptZero", "negative"},
      {SignDisplay::AUTO, SignDisplay::NEVER, SignDisplay::ALWAYS,
       SignDisplay::EXCEPT_ZERO, SignDisplay::NEGATIVE},
      SignDisplay::AUTO);
  MAYBE_RETURN(maybe_sign_display, MaybeHandle<JSNumberFormat>());
  SignDisplay sign_display = maybe_sign_display.FromJust();

  // 33. Set numberFormat.[[SignDisplay]] to signDisplay.
  // The default sign in ICU is UNUM_SIGN_AUTO which is mapped from
  // SignDisplay::AUTO and CurrencySign::STANDARD so we can skip setting
  // under that values for optimization.
  if (sign_display != SignDisplay::AUTO ||
      currency_sign != CurrencySign::STANDARD) {
    settings = settings.sign(ToUNumberSignDisplay(sign_display, currency_sign));
  }

  // 25. Let dataLocaleData be localeData.[[<dataLocale>]].
  //
  // 26. Let patterns be dataLocaleData.[[patterns]].
  //
  // 27. Assert: patterns is a record (see 11.3.3).
  //
  // 28. Let stylePatterns be patterns.[[<style>]].
  //
  // 29. Set numberFormat.[[PositivePattern]] to
  // stylePatterns.[[positivePattern]].
  //
  // 30. Set numberFormat.[[NegativePattern]] to
  // stylePatterns.[[negativePattern]].
  //
  icu::number::LocalizedNumberFormatter fmt = settings.locale(icu_locale);

  DirectHandle<Managed<icu::number::LocalizedNumberFormatter>>
      managed_number_formatter =
          Managed<icu::number::LocalizedNumberFormatter>::From(
              isolate, 0,
              std::make_shared<icu::number::LocalizedNumberFormatter>(fmt));

  // Now all properties are ready, so we can allocate the result object.
  Handle<JSNumberFormat> number_format = Cast<JSNumberFormat>(
      isolate->factory()->NewFastOrSlowJSObjectFromMap(map));
  DisallowGarbageCollection no_gc;
  number_format->set_locale(*locale_str);

  number_format->set_icu_number_formatter(*managed_number_formatter);
  number_format->set_bound_format(*factory->undefined_value());

  // 31. Return numberFormat.
  return number_format;
}

namespace {

icu::number::FormattedNumber FormatDecimalString(
    Isolate* isolate,
    const icu::number::LocalizedNumberFormatter& number_format,
    Handle<String> string, UErrorCode& status) {
  string = String::Flatten(isolate, string);
  DisallowGarbageCollection no_gc;
  const String::FlatContent& flat = string->GetFlatContent(no_gc);
  int32_t length = static_cast<int32_t>(string->length());
  if (flat.IsOneByte()) {
    const char* char_buffer =
        reinterpret_cast<const char*>(flat.ToOneByteVector().begin());
    return number_format.formatDecimal({char_buffer, length}, status);
  }
  return number_format.formatDecimal({string->ToCString().get(), length},
                                     status);
}

}  // namespace

bool IntlMathematicalValue::IsNaN() const { return i::IsNaN(*value_); }

MaybeHandle<String> IntlMathematicalValue::ToString(Isolate* isolate) const {
  DirectHandle<String> string;
  if (IsNumber(*value_)) {
    return isolate->factory()->NumberToString(value_);
  }
  if (IsBigInt(*value_)) {
    return BigInt::ToString(isolate, Cast<BigInt>(value_));
  }
  DCHECK(IsString(*value_));
  return Cast<String>(value_);
}

namespace {
Maybe<icu::number::FormattedNumber> IcuFormatNumber(
    Isolate* isolate,
    const icu::number::LocalizedNumberFormatter& number_format,
    Handle<Object> numeric_obj) {
  icu::number::FormattedNumber formatted;
  // If it is BigInt, handle it differently.
  UErrorCode status = U_ZERO_ERROR;
  if (IsBigInt(*numeric_obj)) {
    auto big_int = Cast<BigInt>(numeric_obj);
    Handle<String> big_int_string;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, big_int_string,
                                     BigInt::ToString(isolate, big_int),
                                     Nothing<icu::number::FormattedNumber>());
    big_int_string = String::Flatten(isolate, big_int_string);
    DisallowGarbageCollection no_gc;
    const String::FlatContent& flat = big_int_string->GetFlatContent(no_gc);
    int32_t length = static_cast<int32_t>(big_int_string->length());
    DCHECK(flat.IsOneByte());
    const char* char_buffer =
        reinterpret_cast<const char*>(flat.ToOneByteVector().begin());
    formatted = number_format.formatDecimal({char_buffer, length}, status);
  } else {
    if (IsString(*numeric_obj)) {
      // TODO(ftang) Correct the handling of string after the resolution of
      // https://github.com/tc39/proposal-intl-numberformat-v3/pull/82
      DirectHandle<String> string =
          String::Flatten(isolate, Cast<String>(numeric_obj));
      DisallowGarbageCollection no_gc;
      const String::FlatContent& flat = string->GetFlatContent(no_gc);
      int32_t length = static_cast<int32_t>(string->length());
      if (flat.IsOneByte()) {
        const char* char_buffer =
            reinterpret_cast<const char*>(flat.ToOneByteVector().begin());
        formatted = number_format.formatDecimal({char_buffer, length}, status);
      } else {
        // We may have two bytes string such as "漢 123456789".substring(2)
        // The value will be "123456789" only in ASCII range, but encoded
        // in two bytes string.
        // ICU accepts UTF8 string, so if the source is two-byte encoded,
        // copy into a UTF8 string via ToCString.
        int32_t length = static_cast<int32_t>(string->length());
        formatted = number_format.formatDecimal(
            {string->ToCString().get(), length}, status);
      }
    } else {
      double number = IsNaN(*numeric_obj)
                          ? std::numeric_limits<double>::quiet_NaN()
                          : Object::NumberValue(*numeric_obj);
      formatted = number_format.formatDouble(number, status);
    }
  }
  if (U_FAILURE(status)) {
    // This happen because of icu data trimming trim out "unit".
    // See https://bugs.chromium.org/p/v8/issues/detail?id=8641
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NewTypeError(MessageTemplate::kIcuError),
                                 Nothing<icu::number::FormattedNumber>());
  }
  return Just(std::move(formatted));
}

}  // namespace

Maybe<icu::number::FormattedNumber> IntlMathematicalValue::FormatNumeric(
    Isolate* isolate,
    const icu::number::LocalizedNumberFormatter& number_format,
    const IntlMathematicalValue& x) {
  if (IsString(*x.value_)) {
    Handle<String> string;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, string, x.ToString(isolate),
                                     Nothing<icu::number::FormattedNumber>());
    UErrorCode status = U_ZERO_ERROR;
    icu::number::FormattedNumber result =
        FormatDecimalString(isolate, number_format, string, status);
    if (U_FAILURE(status)) {
      THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                   NewTypeError(MessageTemplate::kIcuError),
                                   Nothing<icu::number::FormattedNumber>());
    }
    return Just(std::move(result));
  }
  CHECK(IsNumber(*x.value_) || IsBigInt(*x.value_));
  return IcuFormatNumber(isolate, number_format, x.value_);
}

Maybe<icu::number::FormattedNumberRange> IntlMathematicalValue::FormatRange(
    Isolate* isolate,
    const icu::number::LocalizedNumberRangeFormatter& number_range_format,
    const IntlMathematicalValue& x, const IntlMathematicalValue& y) {
  icu::Formattable x_formatable;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, x_formatable, x.ToFormattable(isolate),
      Nothing<icu::number::FormattedNumberRange>());

  icu::Formattable y_formatable;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, y_formatable, y.ToFormattable(isolate),
      Nothing<icu::number::FormattedNumberRange>());

  UErrorCode status = U_ZERO_ERROR;
  icu::number::FormattedNumberRange result =
      number_range_format.formatFormattableRange(x_formatable, y_formatable,
                                                 status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NewTypeError(MessageTemplate::kIcuError),
                                 Nothing<icu::number::FormattedNumberRange>());
  }

  return Just(std::move(result));
}

namespace {
// Return the index of the end of leading white space or line terminator
// and the index of the start of trailing white space or line terminator.
template <typename Char>
std::pair<int, int> FindLeadingAndTrailingWhiteSpaceOrLineTerminator(
    base::Vector<const Char> src) {
  size_t leading_end = 0;

  // Find the length of leading StrWhiteSpaceChar.
  while (leading_end < src.size() &&
         IsWhiteSpaceOrLineTerminator(
             static_cast<uint16_t>(src.at(leading_end)))) {
    leading_end++;
  }
  size_t trailing_start = src.size();
  // Find the start of the trailing StrWhiteSpaceChar
  while (trailing_start > leading_end &&
         IsWhiteSpaceOrLineTerminator(
             static_cast<uint16_t>(src.at(trailing_start - 1)))) {
    trailing_start--;
  }
  return std::make_pair(leading_end, trailing_start);
}

Handle<String> TrimWhiteSpaceOrLineTerminator(Isolate* isolate,
                                              Handle<String> string) {
  string = String::Flatten(isolate, string);
  std::pair<int, uint32_t> whitespace_offsets;
  {
    DisallowGarbageCollection no_gc;
    String::Fl
```