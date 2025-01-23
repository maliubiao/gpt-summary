Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for the functionality of the `FontMatchingMetrics` class, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning with inputs/outputs, and common user/programming errors.

2. **Initial Code Scan (High-Level):**  Immediately, keywords like "metrics," "histogram," "ukm_recorder," and mentions of font lookups stand out. The class name itself, `FontMatchingMetrics`, strongly suggests it's about tracking and reporting data related to how the browser finds and selects fonts. The inclusion of privacy budget related headers (`privacy_budget`) also hints at a focus on preventing fingerprinting.

3. **Identify Key Functionality Areas:**  Based on the method names and data members, I can categorize the functionalities:

    * **Reporting Font Match Success/Failure:**  Methods like `ReportSuccessfulFontFamilyMatch`, `ReportFailedFontFamilyMatch`, `ReportSuccessfulLocalFontMatch`, `ReportFailedLocalFontMatch`. These seem straightforward: record whether a font lookup was successful or not.

    * **Tracking Font Existence:** `ReportLocalFontExistenceByUniqueOrFamilyName`, `ReportLocalFontExistenceByUniqueNameOnly`. These are similar to the success/failure methods but are explicitly about whether a font exists.

    * **Recording Font Lookups (Detailed):** `ReportFontLookupByUniqueOrFamilyName`, `ReportFontLookupByUniqueNameOnly`, `ReportFontLookupByFallbackCharacter`, `ReportLastResortFallbackFontLookup`, `ReportFontFamilyLookupByGenericFamily`. These methods appear to capture different ways the browser tries to find the right font.

    * **Emoji Metrics:** `ReportEmojiSegmentGlyphCoverage`. This is a separate concern, tracking how well emoji are rendered.

    * **Privacy/Fingerprinting Prevention:** The use of `IdentifiableToken`, `IdentifiabilityMetricBuilder`, and the sampling logic within the `Report...` methods clearly points towards this. The goal is to collect font information in a way that's useful for understanding font matching but doesn't easily reveal a user's specific font configuration for fingerprinting.

    * **Data Aggregation and Reporting:** `PublishIdentifiabilityMetrics`, `PublishEmojiGlyphMetrics`, `PublishAllMetrics`. These methods handle the actual sending of the collected metrics.

    * **Hashing:** `GetHashForFontData`, `GetPostScriptNameTokenForFontData`. These functions are used to create anonymized representations of font data, crucial for privacy.

    * **Timing:** `identifiability_metrics_timer_`. This suggests batched reporting of privacy metrics.

4. **Deep Dive into Key Methods (Logical Reasoning):**

    * **`ReportFontLookupByUniqueOrFamilyName`:**  I see it takes a font name and `FontDescription`. The `IdentifiableTokenBuilder` is used with `GetTokenBuilderWithFontSelectionRequest` and the font name. This strongly suggests that the *combination* of the requested font properties and the font name is being tracked. The `InsertFontHashIntoMap` then links this input to the *resulting* font data's hash.

    * **`InsertFontHashIntoMap`:** The `DCHECK` confirms this is only used when sampling is enabled. It prevents duplicate entries and uses `GetHashForFontData` to anonymize the font. The logic about `kLocalFontLoadPostScriptName` indicates that the postscript name is also being tracked under specific conditions.

    * **Privacy Logic (General):** The frequent checks like `IdentifiabilityStudySettings::Get()->ShouldSampleType(...)` are crucial. They dictate *when* data is collected, highlighting the focus on controlling information leakage.

5. **Relating to Web Technologies (JavaScript, HTML, CSS):**

    * **CSS:**  The most direct connection is through CSS `font-family` properties. When CSS specifies a font, this code is involved in finding the best match. The different `ReportFontLookupBy...` methods correspond to various stages of the font matching process initiated by CSS.

    * **JavaScript:**  JavaScript can indirectly influence font matching by manipulating the DOM and styles, thus triggering CSS font selections. More directly, the Font Access API (if enabled) would interact with this code. Also, JavaScript performance metrics might correlate with font matching performance.

    * **HTML:**  The `<style>` tag and inline styles in HTML directly contribute to the CSS that triggers font lookups. The `lang` attribute in HTML can also influence font selection (script detection).

6. **Hypothesize Inputs and Outputs:** For specific methods like `ReportFontLookupByUniqueOrFamilyName`, I can create concrete examples:

    * **Input:**  `name = "Arial"`, `font_description` specifies bold, 16px. `resulting_font_data` represents the actual Arial Bold font found.
    * **Output:**  A new entry in `font_lookups_by_unique_or_family_name_` with a key derived from the font description and "Arial," and a value that's the hash of the Arial Bold font data.

7. **Identify Potential User/Programming Errors:**

    * **CSS `font-family` typos:**  A common user error directly impacts this code. A misspelled font name will lead to failed lookups.
    * **Overly specific font stacks:**  Specifying many fonts in a `font-family` list, especially rare ones, increases the chances of triggering more complex fallback logic tracked by this code.
    * **Assuming font availability:** Developers might assume a font is present on a user's system when it's not.

8. **Structure the Answer:**  Organize the findings into clear sections: Functionality, Relation to Web Technologies, Logical Reasoning, and User/Programming Errors. Use bullet points and code snippets to make the explanation easy to understand.

9. **Refine and Review:**  Read through the generated explanation to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where more detail could be added. For instance, initially, I might not have explicitly mentioned the `Dactyloscoper` tracing, but noticing the calls to it adds another layer of understanding.
This C++ file, `font_matching_metrics.cc`, within the Chromium Blink engine, is responsible for **collecting and reporting metrics related to the font matching process**. Its primary goal is to understand how fonts are being requested and resolved in the browser, likely for performance analysis, identifying areas for improvement, and potentially for privacy-related measurements.

Here's a breakdown of its functionalities:

**1. Tracking Font Lookup Success and Failure:**

* **`ReportSuccessfulFontFamilyMatch(const AtomicString& font_family_name)`:**  Records when a font family name (e.g., "Arial") is successfully matched to a local font.
* **`ReportFailedFontFamilyMatch(const AtomicString& font_family_name)`:** Records when a font family name cannot be matched.
* **`ReportSuccessfulLocalFontMatch(const AtomicString& font_name)`:** Records when a specific font name (e.g., "Arial-Bold") is successfully matched.
* **`ReportFailedLocalFontMatch(const AtomicString& font_name)`:** Records when a specific font name cannot be matched.

**2. Tracking Font Existence:**

* **`ReportLocalFontExistenceByUniqueOrFamilyName(const AtomicString& font_name, bool font_exists)`:** Records whether a font with a given unique name or family name exists on the system. This is used for privacy analysis (identifiability).
* **`ReportLocalFontExistenceByUniqueNameOnly(const AtomicString& font_name, bool font_exists)`:** Similar to the above, but specifically for lookups by unique font name.

**3. Recording Detailed Font Lookup Information:**

* **`ReportFontLookupByUniqueOrFamilyName(...)`:** Records details when a font is looked up using either its unique name or family name. This includes the requested name, the `FontDescription` (specifying style, weight, etc.), and the resulting `SimpleFontData`.
* **`ReportFontLookupByUniqueNameOnly(...)`:** Records details when a font is looked up using only its unique name.
* **`ReportFontLookupByFallbackCharacter(...)`:** Records when a fallback character is used to find a suitable font. This happens when the requested font doesn't have a glyph for a specific character.
* **`ReportLastResortFallbackFontLookup(...)`:** Records when the browser resorts to a last-resort fallback font (like "serif" or "sans-serif").
* **`ReportFontFamilyLookupByGenericFamily(...)`:** Records when a font is looked up based on a generic family name like "serif", "sans-serif", or "monospace". It also includes the script and the resulting font name.

**4. Collecting Emoji Rendering Metrics:**

* **`ReportEmojiSegmentGlyphCoverage(unsigned num_clusters, unsigned num_broken_clusters)`:** Tracks the number of emoji clusters processed and how many of them were broken (didn't render correctly).

**5. Privacy-Focused Metrics (Using the Privacy Budget mechanism):**

* The code extensively uses `IdentifiabilityStudySettings`, `IdentifiableToken`, and `IdentifiabilityMetricBuilder`. This indicates a focus on collecting font-related data in a way that contributes to understanding browser identifiability without revealing too much specific information about the user's system. Hashes and benign case-folding are used to anonymize data.
* The various `ReportLocalFontExistence...` and `ReportFontLookupBy...` methods, when sampling is enabled via `IdentifiabilityStudySettings`, record the *existence* of fonts or the *outcome* of lookups in a privacy-preserving way.
* **`PublishIdentifiabilityMetrics()`:**  Bundles up the collected privacy-related font metrics and sends them (via `ukm_recorder_`).

**6. General Metrics Reporting:**

* **`PublishEmojiGlyphMetrics()`:** Sends the emoji rendering metrics to a histogram ("Blink.Fonts.EmojiClusterBrokenness").
* **`PublishAllMetrics()`:** Calls both `PublishIdentifiabilityMetrics()` and `PublishEmojiGlyphMetrics()`.

**7. Internal Helpers:**

* **`GetHashForFontData(const SimpleFontData* font_data)`:**  Calculates a hash of the font data, used for privacy-preserving identification of fonts.
* **`GetPostScriptNameTokenForFontData(const SimpleFontData* font_data)`:**  Gets a token representing the PostScript name of the font, also for privacy analysis.
* **`IdentifiabilityMetricsTimerFired()`:**  A timer-based function to periodically publish the identifiability metrics.
* **`OnFontLookup()`:**  Starts the timer for publishing identifiability metrics when a font lookup occurs (if not already active).

**Relationship to JavaScript, HTML, and CSS:**

This code is deeply intertwined with how the browser renders web pages defined by HTML, styled by CSS, and potentially manipulated by JavaScript.

* **CSS `font-family` Property (Direct Relationship):** When a CSS rule specifies `font-family: "Arial", sans-serif;`, this code is directly involved in the font matching process.
    * **Example:** If the CSS specifies `font-family: "MyCustomFont", serif;`, and "MyCustomFont" is installed on the user's system:
        * `ReportSuccessfulFontFamilyMatch("MyCustomFont")` might be called.
        * `ReportFontLookupByUniqueOrFamilyName("MyCustomFont", ..., resulting_font_data_for_MyCustomFont)` would record the lookup.
    * If "MyCustomFont" is *not* installed, and the browser falls back to a serif font:
        * `ReportFailedFontFamilyMatch("MyCustomFont")` would be called.
        * `ReportFontFamilyLookupByGenericFamily("serif", ...)` would record the fallback lookup.

* **HTML `lang` Attribute (Indirect Relationship):** The `lang` attribute on HTML elements can influence font selection (e.g., choosing fonts that support specific scripts). This could indirectly affect which font lookup paths are taken and the metrics recorded.

* **JavaScript Font Access API (Potential Relationship):** If JavaScript uses APIs to query available fonts or load custom fonts, this code could be involved in tracking those operations.

* **Emoji Rendering (Direct Relationship):** When the browser encounters emoji characters in HTML, this code tracks how well those emoji are rendered using the `ReportEmojiSegmentGlyphCoverage` function.

**Logical Reasoning (Hypothetical Input and Output):**

**Scenario:** A webpage uses the following CSS:

```css
body {
  font-family: "Roboto-Regular", "Arial", sans-serif;
}
```

Let's assume the user has "Arial" installed but not "Roboto-Regular".

**Assumptions:**

* `IdentifiabilityStudySettings` is configured to sample `kLocalFontLookupByUniqueOrFamilyName` and `kGenericFontLookup`.

**Hypothetical Events and Metric Reporting:**

1. **Lookup for "Roboto-Regular":**
   * Input to `ReportFontLookupByUniqueOrFamilyName`: `name = "Roboto-Regular"`, `FontDescription` specifying regular weight, etc.
   * Since "Roboto-Regular" is not found, the `resulting_font_data` would likely represent a temporary fallback or an indication of failure.
   * Output: An entry in `font_lookups_by_unique_or_family_name_` (if sampling is enabled) with a key derived from the font description and "Roboto-Regular", and a value representing the hash of the fallback font data or a special "not found" hash.
   * `ReportFailedFontFamilyMatch("Roboto-Regular")` would be called.

2. **Lookup for "Arial":**
   * Input to `ReportFontLookupByUniqueOrFamilyName`: `name = "Arial"`, same `FontDescription`.
   * The browser finds the local "Arial" font.
   * Output: An entry in `font_lookups_by_unique_or_family_name_` with a key derived from the font description and "Arial", and a value representing the hash of the "Arial" font data.
   * `ReportSuccessfulFontFamilyMatch("Arial")` would be called.

3. **Lookup for "sans-serif":**
   * Input to `ReportFontFamilyLookupByGenericFamily`: `generic_font_family_name = "sans-serif"`, `script` (e.g., `USCRIPT_LATIN`), `generic_family_type` (likely `kStandardFamily` or similar).
   * The browser resolves this to a specific sans-serif font available on the system (e.g., "Helvetica" or "Liberation Sans").
   * Output: An entry in `generic_font_lookups_` with a key derived from "sans-serif" and the script, and a value of "Helvetica" (or the actual resolved font name, case-insensitively).

**User or Programming Common Usage Errors:**

1. **Typographical Errors in CSS `font-family`:**
   * **Example:** `font-family: "Ariial";` (misspelling "Arial").
   * **Impact:** `ReportFailedFontFamilyMatch("Ariial")` would be called. The browser would then proceed to the next font in the stack or the generic family, leading to potentially unexpected font rendering.

2. **Assuming Font Availability:**
   * **Example:** A web developer uses `font-family: "MyCustomFont";` without providing fallback fonts, assuming all users have "MyCustomFont" installed.
   * **Impact:** If the user doesn't have "MyCustomFont", `ReportFailedFontFamilyMatch("MyCustomFont")` would be called, and the browser would use a default or generic font, potentially breaking the intended design.

3. **Overly Specific Font Names:**
   * **Example:** Using very specific font names like `font-family: "Arial-BoldItalic-Condensed";`.
   * **Impact:**  This increases the chance of a failed match. If the exact font with that specific variant name isn't found, the browser might not find a close enough match automatically. More fallback lookups would be triggered.

4. **Not Providing Fallback Fonts:**
   * **Example:** `font-family: "ExoticUniqueFont";`.
   * **Impact:** If "ExoticUniqueFont" is not available, the browser will likely use a very basic default font, which might not be visually appealing or fit the design. The metrics would show a failed lookup and a fallback to a generic font.

5. **Incorrect `lang` Attribute Usage:**
   * **Example:**  Setting `lang="zh"` (Chinese) on text that is actually in English.
   * **Impact:**  The font matching process might prioritize fonts suitable for Chinese characters, leading to potentially incorrect or suboptimal font selection for the English text. This could indirectly influence the metrics recorded for generic font lookups based on the script.

In summary, `font_matching_metrics.cc` plays a crucial role in understanding the font matching behavior within the Chromium browser, providing valuable data for performance analysis, identifying potential issues, and contributing to privacy-preserving measurements related to font usage. It directly interacts with the font selection process triggered by CSS and indirectly by HTML and JavaScript.

### 提示词
```
这是目录为blink/renderer/core/frame/font_matching_metrics.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/font_matching_metrics.h"

#include "base/metrics/histogram_macros.h"
#include "base/task/single_thread_task_runner.h"
#include "services/metrics/public/cpp/ukm_recorder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_surface.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_token.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/dactyloscoper.h"
#include "third_party/blink/renderer/platform/fonts/font_global_context.h"
#include "third_party/blink/renderer/platform/privacy_budget/identifiability_digest_helpers.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"

namespace {

template <typename T>
HashSet<T> SetIntersection(const HashSet<T>& a, const HashSet<T>& b) {
  HashSet<T> result;
  for (const T& a_value : a) {
    if (b.Contains(a_value)) {
      result.insert(a_value);
    }
  }
  return result;
}

}  // namespace

namespace blink {

namespace {

bool IdentifiabilityStudyShouldSampleFonts() {
  return IdentifiabilityStudySettings::Get()->ShouldSampleAnyType({
      IdentifiableSurface::Type::kLocalFontLookupByUniqueOrFamilyName,
      IdentifiableSurface::Type::kLocalFontLookupByUniqueNameOnly,
      IdentifiableSurface::Type::kLocalFontLookupByFallbackCharacter,
      IdentifiableSurface::Type::kLocalFontLookupAsLastResort,
      IdentifiableSurface::Type::kGenericFontLookup,
      IdentifiableSurface::Type::kLocalFontLoadPostScriptName,
      IdentifiableSurface::Type::kLocalFontExistenceByUniqueNameOnly,
      IdentifiableSurface::Type::kLocalFontExistenceByUniqueOrFamilyName,
  });
}

}  // namespace

FontMatchingMetrics::FontMatchingMetrics(
    ExecutionContext* execution_context,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : ukm_recorder_(execution_context->UkmRecorder()),
      source_id_(execution_context->UkmSourceID()),
      execution_context_(execution_context),
      identifiability_metrics_timer_(
          task_runner,
          this,
          &FontMatchingMetrics::IdentifiabilityMetricsTimerFired) {}

void FontMatchingMetrics::ReportSuccessfulFontFamilyMatch(
    const AtomicString& font_family_name) {
  if (font_family_name.IsNull()) {
    return;
  }
  ReportLocalFontExistenceByUniqueOrFamilyName(font_family_name,
                                               /*font_exists=*/true);
}

void FontMatchingMetrics::ReportFailedFontFamilyMatch(
    const AtomicString& font_family_name) {
  if (font_family_name.IsNull()) {
    return;
  }
  ReportLocalFontExistenceByUniqueOrFamilyName(font_family_name,
                                               /*font_exists=*/false);
}

void FontMatchingMetrics::ReportSuccessfulLocalFontMatch(
    const AtomicString& font_name) {
  if (font_name.IsNull()) {
    return;
  }
  ReportLocalFontExistenceByUniqueNameOnly(font_name, /*font_exists=*/true);
}

void FontMatchingMetrics::ReportFailedLocalFontMatch(
    const AtomicString& font_name) {
  if (font_name.IsNull()) {
    return;
  }
  ReportLocalFontExistenceByUniqueNameOnly(font_name, /*font_exists=*/false);
}

void FontMatchingMetrics::ReportLocalFontExistenceByUniqueOrFamilyName(
    const AtomicString& font_name,
    bool font_exists) {
  if (font_name.IsNull()) {
    return;
  }
  if (!IdentifiabilityStudySettings::Get()->ShouldSampleType(
          IdentifiableSurface::Type::kLocalFontExistenceByUniqueOrFamilyName)) {
    return;
  }
  IdentifiableTokenKey input_key(
      IdentifiabilityBenignCaseFoldingStringToken(font_name));
  local_font_existence_by_unique_or_family_name_.insert(input_key, font_exists);
}

void FontMatchingMetrics::ReportLocalFontExistenceByUniqueNameOnly(
    const AtomicString& font_name,
    bool font_exists) {
  if (font_name.IsNull()) {
    return;
  }
  if (!IdentifiabilityStudySettings::Get()->ShouldSampleType(
          IdentifiableSurface::Type::kLocalFontExistenceByUniqueNameOnly)) {
    return;
  }
  IdentifiableTokenKey input_key(
      IdentifiabilityBenignCaseFoldingStringToken(font_name));
  local_font_existence_by_unique_name_only_.insert(input_key, font_exists);
}

void FontMatchingMetrics::InsertFontHashIntoMap(IdentifiableTokenKey input_key,
                                                const SimpleFontData* font_data,
                                                TokenToTokenHashMap& hash_map) {
  DCHECK(IdentifiabilityStudyShouldSampleFonts());
  if (hash_map.Contains(input_key)) {
    return;
  }
  IdentifiableToken output_token(GetHashForFontData(font_data));
  hash_map.insert(input_key, output_token);

  // We only record postscript name metrics if both the the broader lookup's
  // type and kLocalFontLoadPostScriptName are allowed. (If the former is not,
  // InsertFontHashIntoMap would not be called.)
  if (!font_data ||
      !IdentifiabilityStudySettings::Get()->ShouldSampleType(
          IdentifiableSurface::Type::kLocalFontLoadPostScriptName)) {
    return;
  }
  IdentifiableTokenKey postscript_name_key(
      GetPostScriptNameTokenForFontData(font_data));
  font_load_postscript_name_.insert(postscript_name_key, output_token);
}

IdentifiableTokenBuilder
FontMatchingMetrics::GetTokenBuilderWithFontSelectionRequest(
    const FontDescription& font_description) {
  IdentifiableTokenBuilder builder;
  builder.AddValue(font_description.GetFontSelectionRequest().GetHash());
  return builder;
}

void FontMatchingMetrics::ReportFontLookupByUniqueOrFamilyName(
    const AtomicString& name,
    const FontDescription& font_description,
    const SimpleFontData* resulting_font_data) {
  Dactyloscoper::TraceFontLookup(
      execution_context_, name, font_description,
      Dactyloscoper::FontLookupType::kUniqueOrFamilyName);
  if (!IdentifiabilityStudySettings::Get()->ShouldSampleType(
          IdentifiableSurface::Type::kLocalFontLookupByUniqueOrFamilyName)) {
    return;
  }
  OnFontLookup();

  IdentifiableTokenBuilder builder =
      GetTokenBuilderWithFontSelectionRequest(font_description);

  // Font name lookups are case-insensitive.
  builder.AddToken(IdentifiabilityBenignCaseFoldingStringToken(name));

  IdentifiableTokenKey input_key(builder.GetToken());
  InsertFontHashIntoMap(input_key, resulting_font_data,
                        font_lookups_by_unique_or_family_name_);
}

void FontMatchingMetrics::ReportFontLookupByUniqueNameOnly(
    const AtomicString& name,
    const FontDescription& font_description,
    const SimpleFontData* resulting_font_data,
    bool is_loading_fallback) {
  // We ignore lookups that result in loading fallbacks for now as they should
  // only be temporary.
  if (is_loading_fallback) {
    return;
  }

  Dactyloscoper::TraceFontLookup(
      execution_context_, name, font_description,
      Dactyloscoper::FontLookupType::kUniqueNameOnly);

  if (!IdentifiabilityStudySettings::Get()->ShouldSampleType(
          IdentifiableSurface::Type::kLocalFontLookupByUniqueNameOnly)) {
    return;
  }
  OnFontLookup();

  IdentifiableTokenBuilder builder =
      GetTokenBuilderWithFontSelectionRequest(font_description);

  // Font name lookups are case-insensitive.
  builder.AddToken(IdentifiabilityBenignCaseFoldingStringToken(name));

  IdentifiableTokenKey input_key(builder.GetToken());
  InsertFontHashIntoMap(input_key, resulting_font_data,
                        font_lookups_by_unique_name_only_);
}

void FontMatchingMetrics::ReportFontLookupByFallbackCharacter(
    UChar32 fallback_character,
    FontFallbackPriority fallback_priority,
    const FontDescription& font_description,
    const SimpleFontData* resulting_font_data) {
  if (!IdentifiabilityStudySettings::Get()->ShouldSampleType(
          IdentifiableSurface::Type::kLocalFontLookupByFallbackCharacter)) {
    return;
  }
  OnFontLookup();

  IdentifiableTokenBuilder builder =
      GetTokenBuilderWithFontSelectionRequest(font_description);
  builder.AddValue(fallback_character)
      .AddToken(IdentifiableToken(fallback_priority));

  IdentifiableTokenKey input_key(builder.GetToken());
  InsertFontHashIntoMap(input_key, resulting_font_data,
                        font_lookups_by_fallback_character_);
}

void FontMatchingMetrics::ReportLastResortFallbackFontLookup(
    const FontDescription& font_description,
    const SimpleFontData* resulting_font_data) {
  if (!IdentifiabilityStudySettings::Get()->ShouldSampleType(
          IdentifiableSurface::Type::kLocalFontLookupAsLastResort)) {
    return;
  }
  OnFontLookup();

  IdentifiableTokenBuilder builder =
      GetTokenBuilderWithFontSelectionRequest(font_description);

  IdentifiableTokenKey input_key(builder.GetToken());
  InsertFontHashIntoMap(input_key, resulting_font_data,
                        font_lookups_as_last_resort_);
}

void FontMatchingMetrics::ReportFontFamilyLookupByGenericFamily(
    const AtomicString& generic_font_family_name,
    UScriptCode script,
    FontDescription::GenericFamilyType generic_family_type,
    const AtomicString& resulting_font_name) {
  if (!IdentifiabilityStudySettings::Get()->ShouldSampleType(
          IdentifiableSurface::Type::kGenericFontLookup)) {
    return;
  }
  OnFontLookup();

  // kStandardFamily/kWebkitBodyFamily lookups override the
  // |generic_font_family_name|. See FontSelector::FamilyNameFromSettings.
  // No need to be case-insensitive as generic names should already be
  // lowercase.
  DCHECK(generic_family_type == FontDescription::kStandardFamily ||
         generic_family_type == FontDescription::kWebkitBodyFamily ||
         generic_font_family_name == generic_font_family_name.LowerASCII());
  IdentifiableToken lookup_name_token = IdentifiabilityBenignStringToken(
      (generic_family_type == FontDescription::kStandardFamily ||
       generic_family_type == FontDescription::kWebkitBodyFamily)
          ? font_family_names::kWebkitStandard
          : generic_font_family_name);

  IdentifiableTokenBuilder builder;
  builder.AddToken(lookup_name_token).AddToken(IdentifiableToken(script));
  IdentifiableTokenKey input_key(builder.GetToken());

  // Font name lookups are case-insensitive.
  generic_font_lookups_.insert(
      input_key,
      IdentifiabilityBenignCaseFoldingStringToken(resulting_font_name));
}

void FontMatchingMetrics::ReportEmojiSegmentGlyphCoverage(
    unsigned num_clusters,
    unsigned num_broken_clusters) {
  total_emoji_clusters_shaped_ += num_clusters;
  total_broken_emoji_clusters_ += num_broken_clusters;
}

void FontMatchingMetrics::PublishIdentifiabilityMetrics() {
  if (!IdentifiabilityStudyShouldSampleFonts()) {
    return;
  }

  IdentifiabilityMetricBuilder builder(source_id_);

  std::pair<TokenToTokenHashMap*, IdentifiableSurface::Type>
      hash_maps_with_corresponding_surface_types[] = {
          {&font_lookups_by_unique_or_family_name_,
           IdentifiableSurface::Type::kLocalFontLookupByUniqueOrFamilyName},
          {&font_lookups_by_unique_name_only_,
           IdentifiableSurface::Type::kLocalFontLookupByUniqueNameOnly},
          {&font_lookups_by_fallback_character_,
           IdentifiableSurface::Type::kLocalFontLookupByFallbackCharacter},
          {&font_lookups_as_last_resort_,
           IdentifiableSurface::Type::kLocalFontLookupAsLastResort},
          {&generic_font_lookups_,
           IdentifiableSurface::Type::kGenericFontLookup},
          {&font_load_postscript_name_,
           IdentifiableSurface::Type::kLocalFontLoadPostScriptName},
          {&local_font_existence_by_unique_or_family_name_,
           IdentifiableSurface::Type::kLocalFontExistenceByUniqueOrFamilyName},
          {&local_font_existence_by_unique_name_only_,
           IdentifiableSurface::Type::kLocalFontExistenceByUniqueNameOnly},
      };

  for (const auto& surface_entry : hash_maps_with_corresponding_surface_types) {
    TokenToTokenHashMap* hash_map = surface_entry.first;
    const IdentifiableSurface::Type surface_type = surface_entry.second;
    if (IdentifiabilityStudySettings::Get()->ShouldSampleType(surface_type)) {
      for (const auto& individual_lookup : *hash_map) {
        builder.Add(IdentifiableSurface::FromTypeAndToken(
                        surface_type, individual_lookup.key.token),
                    individual_lookup.value);
      }
    }
    hash_map->clear();
  }

  builder.Record(ukm_recorder_);
}

void FontMatchingMetrics::PublishEmojiGlyphMetrics() {
  DCHECK_LE(total_broken_emoji_clusters_, total_emoji_clusters_shaped_);
  if (total_emoji_clusters_shaped_) {
    double percentage = static_cast<double>(total_broken_emoji_clusters_) /
                        total_emoji_clusters_shaped_;
    UMA_HISTOGRAM_PERCENTAGE("Blink.Fonts.EmojiClusterBrokenness",
                             static_cast<int>(round(percentage * 100)));
  }
}

void FontMatchingMetrics::OnFontLookup() {
  DCHECK(IdentifiabilityStudyShouldSampleFonts());
  if (!identifiability_metrics_timer_.IsActive()) {
    identifiability_metrics_timer_.StartOneShot(base::Minutes(1), FROM_HERE);
  }
}

void FontMatchingMetrics::IdentifiabilityMetricsTimerFired(TimerBase*) {
  PublishIdentifiabilityMetrics();
}

void FontMatchingMetrics::PublishAllMetrics() {
  PublishIdentifiabilityMetrics();
  PublishEmojiGlyphMetrics();
}

int64_t FontMatchingMetrics::GetHashForFontData(
    const SimpleFontData* font_data) {
  return font_data ? FontGlobalContext::Get()
                         .GetOrComputeTypefaceDigest(font_data->PlatformData())
                         .ToUkmMetricValue()
                   : 0;
}

IdentifiableToken FontMatchingMetrics::GetPostScriptNameTokenForFontData(
    const SimpleFontData* font_data) {
  DCHECK(font_data);
  return FontGlobalContext::Get().GetOrComputePostScriptNameDigest(
      font_data->PlatformData());
}

}  // namespace blink
```