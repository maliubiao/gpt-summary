Response: Let's break down the thought process for analyzing this C++ unit test file.

**1. Initial Understanding: What is the Goal?**

The file name `manifest_icon_selector_unittest.cc` immediately tells us this is a test file. The `manifest_icon_selector` part suggests it's testing some logic related to selecting icons from a manifest. In the context of web development, a "manifest" usually refers to a web app manifest, which describes metadata about a web application, including its icons.

**2. High-Level Structure Examination:**

* **Includes:** The `#include` directives tell us the code uses `ManifestIconSelector` (the class being tested), standard C++ library components (`string`, `vector`), base library functionality (`base/strings/utf_string_conversions.h`), and Google Test (`testing/gtest/include/gtest/gtest.h`). This confirms it's a unit test using the Google Test framework.
* **Namespace:** The code is within the `blink` namespace, and then has an anonymous namespace `namespace { ... }`. Anonymous namespaces are used for internal linkage, meaning the constants inside are only visible within this file.
* **Test Fixture:** The `ManifestIconSelectorTest` class inherits from `testing::TestWithParam<bool>`. This means the tests within this class will be run with different parameter values – in this case, `true` and `false`. This likely controls whether the tests are running in a "square only" mode or a more general mode.
* **Helper Functions:** The `CreateIcon` function is a utility for easily creating `blink::Manifest::ImageResource` objects for the tests. The `width_to_height_ratio` function dynamically returns the expected ratio based on the test parameter. The `FindBestMatchingIcon` function calls either `ManifestIconSelector::FindBestMatchingSquareIcon` or `ManifestIconSelector::FindBestMatchingIcon` based on the test parameter. This is a key indicator of the core functionality being tested.
* **Test Cases:**  The `TEST_P` macros define the individual test cases. The `_P` suffix indicates they are parameterized tests, using the boolean parameter from the test fixture.

**3. Functionality Deduction (Based on Test Names and Logic):**

Now, the real work begins – understanding *what* each test case is testing. We go through each `TEST_P` and infer its purpose:

* **`NoIcons`:** Tests the behavior when no icons are provided. Expects an empty URL.
* **`NoSizes`:** Tests the behavior when an icon has no specified sizes. Expects the icon to be ignored.
* **`MIMETypeFiltering`:** Tests that icons with invalid or non-image MIME types are filtered out. It also verifies that valid image MIME types (png, gif, jpeg) are accepted. *Connection to web standards:* This directly relates to how browsers interpret the `type` attribute of `<link rel="icon">` or the `icons` member in a web app manifest.
* **`PurposeFiltering`:** Tests the filtering of icons based on their `purpose` attribute (e.g., "any", "monochrome"). *Connection to web standards:* This also reflects the `purpose` member in a web app manifest, used to specify the intended use of an icon.
* **`IdealSizeIsUsedFirst`:**  Tests the preference for icons matching the `ideal_icon_size_in_px`.
* **`FirstIconWithIdealSizeIsUsedFirst`:** Tests that among icons with the ideal size, the first one in the list is selected.
* **`FallbackToSmallestLargerIcon`:** Tests the fallback mechanism when an exact match isn't found – choosing the smallest icon that's larger than the ideal size.
* **`FallbackToLargestIconLargerThanMinimum`:** Tests that if no icon matches the ideal size, it falls back to the largest icon that is still larger than the `minimum_icon_size_in_px`.
* **`IdealVeryCloseToMinimumMatches`:** Tests the boundary condition where the ideal size is very close to the minimum size.
* **`SizeVeryCloseToMinimumMatches`:** Tests the boundary condition where an available size is very close to the minimum size.
* **`IconsWithInvalidDimensionsAreIgnored`:** Tests that icons with invalid dimensions (non-square in "square only" mode, incorrect aspect ratio in general mode) are ignored. *Connection to web standards:* This relates to the expected shapes and aspect ratios of icons.
* **`ClosestIconToIdeal`:** A series of sub-tests specifically focusing on selecting the icon whose size is closest to the ideal size.
* **`UseAnyIfNoIdealSize`:** Tests the behavior when icons with the special "any" size (represented by `gfx::Size(0, 0)`) are present and how they are chosen in the absence of an ideal size match.

**4. Relationship to Web Technologies (JavaScript, HTML, CSS):**

As identified in the functionality deduction, the core connection lies with the **Web App Manifest**.

* **HTML:**  While not directly tested here, the manifest is often referenced in the HTML using a `<link>` tag: `<link rel="manifest" href="/manifest.json">`. The functionality tested here determines which icon, specified *within* the manifest, will be used.
* **JavaScript:** JavaScript code running on a web page might interact with the manifest to get information about the application, including its icons. The `ManifestIconSelector` logic ensures the correct icon URL is available to such JavaScript code.
* **CSS:**  CSS itself doesn't directly interact with the manifest icon selection process. However, once an icon URL is chosen (by the logic being tested), that URL can be used in CSS to style elements, for example, setting a favicon or a custom cursor.

**5. Logical Reasoning and Assumptions:**

The tests implicitly assume certain things:

* **Icon Size Matching Logic:** The core logic of `ManifestIconSelector` is based on comparing icon sizes to the `ideal_icon_size_in_px` and `minimum_icon_size_in_px`. The tests demonstrate different scenarios for these comparisons.
* **Purpose Matching:** The tests assume that icon purposes are matched exactly.
* **MIME Type Validation:** The tests rely on a specific set of valid image MIME types.
* **Prioritization Rules:** The tests demonstrate the prioritization rules when multiple icons are available (e.g., ideal size first, then smallest larger, etc.).

**6. Common Usage Errors (Based on Test Scenarios):**

The tests implicitly highlight potential errors developers might make:

* **Not providing sizes:**  The `NoSizes` test shows that icons without size information are ignored. This means developers need to include the `sizes` attribute in their manifest icon declarations.
* **Using incorrect MIME types:** The `MIMETypeFiltering` test emphasizes the importance of using valid image MIME types for the `type` attribute.
* **Not specifying the `purpose` correctly:**  The `PurposeFiltering` test demonstrates that if the `purpose` doesn't match the intended use, the icon won't be selected.
* **Assuming a specific icon will always be chosen:** The tests with multiple icons of similar sizes or purposes show that the order and specific size values matter. Developers can't blindly assume a particular icon will be picked.
* **Not providing icons that meet minimum size requirements:** The `FallbackToLargestIconLargerThanMinimum` test shows that if no icon is large enough, none will be selected.

By systematically examining the code structure, test case names, and the logic within each test, we can build a comprehensive understanding of the functionality being tested and its relevance to web technologies and potential developer errors.
This C++ unit test file (`manifest_icon_selector_unittest.cc`) is part of the Chromium Blink engine and is specifically designed to test the functionality of the `ManifestIconSelector` class. This class is responsible for selecting the best icon from a list of icons provided in a web app manifest, based on criteria like desired size and purpose.

Here's a breakdown of its functionality and its relation to web technologies:

**Functionality of `manifest_icon_selector_unittest.cc`:**

1. **Testing Icon Selection Logic:** The primary function of this file is to thoroughly test the different scenarios and edge cases of how `ManifestIconSelector` chooses the most appropriate icon. It simulates various sets of icons with different properties (URLs, MIME types, sizes, and purposes) and asserts that the `ManifestIconSelector` returns the expected icon URL.

2. **Testing `FindBestMatchingIcon` and `FindBestMatchingSquareIcon`:** The tests cover both the general `FindBestMatchingIcon` function (which considers aspect ratios) and the `FindBestMatchingSquareIcon` function (which specifically looks for square icons). The parameterized test setup (`testing::TestWithParam<bool>`) allows running the same tests for both scenarios.

3. **Filtering based on Icon Properties:** The tests verify that the selector correctly filters icons based on:
    * **MIME Type:** Only icons with valid image MIME types (like `image/png`, `image/gif`, `image/jpeg`) are considered.
    * **Purpose:** Icons are filtered based on their declared purpose (e.g., `any`, `monochrome`).
    * **Sizes:** The selector considers the available sizes of the icons and compares them to the desired ideal size and minimum size.
    * **Aspect Ratio (for `FindBestMatchingIcon`):**  Icons with extreme width-to-height ratios are ignored.

4. **Prioritization Logic:** The tests implicitly verify the prioritization logic used by the selector:
    * **Exact Ideal Size Match:** If an icon with the exact ideal size is available, it's preferred.
    * **Smallest Larger Icon:** If no exact match is found, the smallest icon that's larger than the ideal size is chosen.
    * **Largest Icon Larger Than Minimum:** If no icon matches the ideal size, it falls back to the largest icon that is still larger than the minimum required size.
    * **Handling of "any" size:**  Icons with size "any" (represented by 0x0) are considered as a fallback when no better match is found.

**Relationship to JavaScript, HTML, CSS:**

This C++ code within the Blink engine directly impacts how web pages are rendered and how web apps behave, particularly in relation to their icons:

* **HTML:** The `<link rel="icon">` tag in HTML, and more importantly, the `icons` member of a **Web App Manifest** (`manifest.json`) are the primary sources of icon information. The `ManifestIconSelector` is used by the browser to process this information and determine which icon to use for various purposes.
    * **Example:** Consider a `manifest.json` like this:
      ```json
      {
        "name": "My Awesome App",
        "icons": [
          {
            "src": "icon-144x144.png",
            "sizes": "144x144",
            "type": "image/png"
          },
          {
            "src": "icon-192x192.png",
            "sizes": "192x192",
            "type": "image/png"
          }
        ]
      }
      ```
      The `ManifestIconSelector`, based on the device's screen density and the desired context (e.g., app launcher icon), would choose either `icon-144x144.png` or `icon-192x192.png`.

* **JavaScript:** While JavaScript doesn't directly interact with the icon selection process, it can be used to fetch the web app manifest and inspect the available icons. The outcome of the `ManifestIconSelector`'s work is what JavaScript developers would observe in terms of the icons being used by the browser.

* **CSS:** CSS can reference icons, for example, as favicons or for custom cursors. The URL of the icon chosen by the `ManifestIconSelector` is what the browser ultimately uses when rendering elements with such CSS rules.

**Logical Reasoning with Assumptions, Inputs, and Outputs:**

Let's take one test case as an example: `TEST_P(ManifestIconSelectorTest, FallbackToSmallestLargerIcon)`

**Assumptions:**

* The `ManifestIconSelector` prioritizes an exact match for the ideal size.
* If no exact match exists, it will choose the smallest icon whose dimensions are greater than the ideal size.

**Hypothetical Input:**

A list of `blink::Manifest::ImageResource` objects representing the following icons:

* `http://foo.com/icon_x1.png` with size 90x90
* `http://foo.com/icon_x2.png` with size 128x128
* `http://foo.com/icon_x3.png` with size 192x192

**Ideal Icon Size:** 96px
**Minimum Icon Size:** 0px
**Purpose:** `Purpose::ANY`

**Expected Output:**

The `FindBestMatchingIcon` function should return the URL `http://foo.com/icon_x2.png`.

**Reasoning:**

1. No icon has the exact ideal size of 96x96.
2. Consider icons larger than 96x96:
   * `icon_x2.png` (128x128)
   * `icon_x3.png` (192x192)
3. `icon_x2.png` is the smallest among the larger icons.

**Common Usage Errors and Examples:**

This test file implicitly highlights common mistakes developers might make when defining icons in their web app manifests:

1. **Not providing sizes:** The `NoSizes` test shows that if an icon doesn't specify its `sizes`, it will be ignored.
   * **Example Error:**
     ```json
     {
       "icons": [
         {
           "src": "icon.png",
           "type": "image/png" // Missing "sizes"
         }
       ]
     }
     ```

2. **Using incorrect MIME types:** The `MIMETypeFiltering` test ensures only valid image MIME types are considered.
   * **Example Error:**
     ```json
     {
       "icons": [
         {
           "src": "icon.svg",
           "sizes": "512x512",
           "type": "application/xml+svg" // Incorrect MIME type for a raster icon context
         }
       ]
     }
     ```

3. **Not providing icons in necessary sizes:** If the developer doesn't provide icons in sizes appropriate for different screen densities, the browser might have to scale icons, leading to blurry results. The tests implicitly encourage providing a range of sizes.

4. **Incorrectly specifying the `purpose`:** If the `purpose` attribute is not set correctly, the icon might not be used in the intended context (e.g., a monochrome icon might be used where a colored one is expected).
   * **Example Error:**
     ```json
     {
       "icons": [
         {
           "src": "maskable_icon.png",
           "sizes": "512x512",
           "type": "image/png",
           "purpose": "any" // Intended for maskable use, but marked as "any"
         }
       ]
     }
     ```

5. **Providing icons with invalid dimensions (for square icon selection):**  The `IconsWithInvalidDimensionsAreIgnored` test for the square icon selector shows that non-square icons will be skipped when square icons are specifically requested.

In summary, `manifest_icon_selector_unittest.cc` plays a crucial role in ensuring the robustness and correctness of the icon selection logic in Chromium. It directly relates to how web app icons are handled and displayed, impacting the user experience and visual presentation of web applications. By testing various scenarios and edge cases, it helps prevent common developer errors and ensures that the best possible icon is chosen based on the specified criteria.

Prompt: 
```
这是目录为blink/common/manifest/manifest_icon_selector_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/common/manifest/manifest_icon_selector.h"

#include <string>
#include <vector>

#include "base/strings/utf_string_conversions.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace blink {

using Purpose = blink::mojom::ManifestImageResource_Purpose;

namespace {
const int kIdealIconSize = 144;
const int kMinimumIconSize = 0;
// The same value as content::ManifestIconDownloader::kMaxWidthToHeightRatio
const int kMaxWidthToHeightRatio = 5;
}  // anonymous namespace

class ManifestIconSelectorTest : public testing::TestWithParam<bool> {
 public:
  ManifestIconSelectorTest() : selects_square_only_(GetParam()) {}
  ~ManifestIconSelectorTest() = default;

 protected:
  blink::Manifest::ImageResource CreateIcon(const std::string& url,
                                            const std::string& type,
                                            const std::vector<gfx::Size> sizes,
                                            Purpose purpose) {
    blink::Manifest::ImageResource icon;
    icon.src = GURL(url);
    icon.type = base::UTF8ToUTF16(type);
    icon.sizes = sizes;
    icon.purpose.push_back(purpose);

    return icon;
  }

  bool selects_square_only() { return selects_square_only_; }

  int width_to_height_ratio() {
    if (selects_square_only_)
      return 1;
    return kMaxWidthToHeightRatio;
  }

  GURL FindBestMatchingIcon(
      const std::vector<blink::Manifest::ImageResource>& icons,
      int ideal_icon_size_in_px,
      int minimum_icon_size_in_px,
      blink::mojom::ManifestImageResource_Purpose purpose) {
    if (selects_square_only_) {
      return ManifestIconSelector::FindBestMatchingSquareIcon(
          icons, ideal_icon_size_in_px, minimum_icon_size_in_px, purpose);
    }
    return ManifestIconSelector::FindBestMatchingIcon(
        icons, ideal_icon_size_in_px, minimum_icon_size_in_px,
        kMaxWidthToHeightRatio, purpose);
  }

 private:
  bool selects_square_only_;
};

TEST_P(ManifestIconSelectorTest, NoIcons) {
  // No icons should return the empty URL.
  std::vector<blink::Manifest::ImageResource> icons;
  GURL url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                                  Purpose::ANY);
  EXPECT_TRUE(url.is_empty());
}

TEST_P(ManifestIconSelectorTest, NoSizes) {
  // Icon with no sizes are ignored.
  std::vector<blink::Manifest::ImageResource> icons;
  icons.push_back(CreateIcon("http://foo.com/icon.png", "",
                             std::vector<gfx::Size>(), Purpose::ANY));

  GURL url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                                  Purpose::ANY);
  EXPECT_TRUE(url.is_empty());
}

TEST_P(ManifestIconSelectorTest, MIMETypeFiltering) {
  // Icons with type specified to a MIME type that isn't a valid image MIME type
  // are ignored.
  std::vector<gfx::Size> sizes;
  sizes.push_back(gfx::Size(width_to_height_ratio() * 1024, 1024));

  std::vector<blink::Manifest::ImageResource> icons;
  icons.push_back(CreateIcon("http://foo.com/icon.png", "image/foo_bar", sizes,
                             Purpose::ANY));
  icons.push_back(
      CreateIcon("http://foo.com/icon.png", "image/", sizes, Purpose::ANY));
  icons.push_back(
      CreateIcon("http://foo.com/icon.png", "image/", sizes, Purpose::ANY));
  icons.push_back(
      CreateIcon("http://foo.com/icon.png", "video/mp4", sizes, Purpose::ANY));

  GURL url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                                  Purpose::ANY);
  EXPECT_TRUE(url.is_empty());

  icons.clear();
  icons.push_back(
      CreateIcon("http://foo.com/icon.png", "image/png", sizes, Purpose::ANY));
  url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                             Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon.png", url.spec());

  icons.clear();
  icons.push_back(
      CreateIcon("http://foo.com/icon.png", "image/gif", sizes, Purpose::ANY));
  url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                             Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon.png", url.spec());

  icons.clear();
  icons.push_back(
      CreateIcon("http://foo.com/icon.png", "image/jpeg", sizes, Purpose::ANY));
  url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                             Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon.png", url.spec());
}

TEST_P(ManifestIconSelectorTest, PurposeFiltering) {
  // Icons with purpose specified to non-matching purpose are ignored.
  std::vector<gfx::Size> sizes_48;
  sizes_48.push_back(gfx::Size(width_to_height_ratio() * 48, 48));

  std::vector<gfx::Size> sizes_96;
  sizes_96.push_back(gfx::Size(width_to_height_ratio() * 96, 96));

  std::vector<gfx::Size> sizes_144;
  sizes_144.push_back(gfx::Size(width_to_height_ratio() * 144, 144));

  std::vector<blink::Manifest::ImageResource> icons;
  icons.push_back(CreateIcon("http://foo.com/icon_48.png", "", sizes_48,
                             Purpose::MONOCHROME));
  icons.push_back(
      CreateIcon("http://foo.com/icon_96.png", "", sizes_96, Purpose::ANY));
  icons.push_back(
      CreateIcon("http://foo.com/icon_144.png", "", sizes_144, Purpose::ANY));

  GURL url =
      FindBestMatchingIcon(icons, 48, kMinimumIconSize, Purpose::MONOCHROME);
  EXPECT_EQ("http://foo.com/icon_48.png", url.spec());

  url = FindBestMatchingIcon(icons, 48, kMinimumIconSize, Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon_96.png", url.spec());

  url = FindBestMatchingIcon(icons, 96, kMinimumIconSize, Purpose::MONOCHROME);
  EXPECT_EQ("http://foo.com/icon_48.png", url.spec());

  url = FindBestMatchingIcon(icons, 96, 96, Purpose::MONOCHROME);
  EXPECT_TRUE(url.is_empty());

  url = FindBestMatchingIcon(icons, 144, kMinimumIconSize, Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon_144.png", url.spec());
}

TEST_P(ManifestIconSelectorTest, IdealSizeIsUsedFirst) {
  // Each icon is marked with sizes that match the ideal icon size.
  std::vector<gfx::Size> sizes_48;
  sizes_48.push_back(gfx::Size(width_to_height_ratio() * 48, 48));

  std::vector<gfx::Size> sizes_96;
  sizes_96.push_back(gfx::Size(width_to_height_ratio() * 96, 96));

  std::vector<gfx::Size> sizes_144;
  sizes_144.push_back(gfx::Size(width_to_height_ratio() * 144, 144));

  std::vector<blink::Manifest::ImageResource> icons;
  icons.push_back(
      CreateIcon("http://foo.com/icon_48.png", "", sizes_48, Purpose::ANY));
  icons.push_back(
      CreateIcon("http://foo.com/icon_96.png", "", sizes_96, Purpose::ANY));
  icons.push_back(
      CreateIcon("http://foo.com/icon_144.png", "", sizes_144, Purpose::ANY));

  GURL url = FindBestMatchingIcon(icons, 48, kMinimumIconSize, Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon_48.png", url.spec());

  url = FindBestMatchingIcon(icons, 96, kMinimumIconSize, Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon_96.png", url.spec());

  url = FindBestMatchingIcon(icons, 144, kMinimumIconSize, Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon_144.png", url.spec());
}

TEST_P(ManifestIconSelectorTest, FirstIconWithIdealSizeIsUsedFirst) {
  // This test has three icons. The first icon is going to be used because it
  // contains the ideal size.
  std::vector<gfx::Size> sizes_1;
  sizes_1.push_back(
      gfx::Size(width_to_height_ratio() * kIdealIconSize, kIdealIconSize));
  sizes_1.push_back(gfx::Size(width_to_height_ratio() * kIdealIconSize * 2,
                              kIdealIconSize * 2));
  sizes_1.push_back(gfx::Size(width_to_height_ratio() * kIdealIconSize * 3,
                              kIdealIconSize * 3));

  std::vector<gfx::Size> sizes_2;
  sizes_2.push_back(gfx::Size(width_to_height_ratio() * 1024, 1024));

  std::vector<gfx::Size> sizes_3;
  sizes_3.push_back(gfx::Size(width_to_height_ratio() * 1024, 1024));

  std::vector<blink::Manifest::ImageResource> icons;
  icons.push_back(
      CreateIcon("http://foo.com/icon_x1.png", "", sizes_1, Purpose::ANY));
  icons.push_back(
      CreateIcon("http://foo.com/icon_x2.png", "", sizes_2, Purpose::ANY));
  icons.push_back(
      CreateIcon("http://foo.com/icon_x3.png", "", sizes_3, Purpose::ANY));

  GURL url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                                  Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon_x1.png", url.spec());

  url = FindBestMatchingIcon(icons, kIdealIconSize * 2, kMinimumIconSize,
                             Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon_x1.png", url.spec());

  url = FindBestMatchingIcon(icons, kIdealIconSize * 3, kMinimumIconSize,
                             Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon_x1.png", url.spec());
}

TEST_P(ManifestIconSelectorTest, FallbackToSmallestLargerIcon) {
  // If there is no perfect icon, the smallest larger icon will be chosen.
  std::vector<gfx::Size> sizes_1;
  sizes_1.push_back(gfx::Size(width_to_height_ratio() * 90, 90));

  std::vector<gfx::Size> sizes_2;
  sizes_2.push_back(gfx::Size(width_to_height_ratio() * 128, 128));

  std::vector<gfx::Size> sizes_3;
  sizes_3.push_back(gfx::Size(width_to_height_ratio() * 192, 192));

  std::vector<blink::Manifest::ImageResource> icons;
  icons.push_back(
      CreateIcon("http://foo.com/icon_x1.png", "", sizes_1, Purpose::ANY));
  icons.push_back(
      CreateIcon("http://foo.com/icon_x2.png", "", sizes_2, Purpose::ANY));
  icons.push_back(
      CreateIcon("http://foo.com/icon_x3.png", "", sizes_3, Purpose::ANY));

  GURL url = FindBestMatchingIcon(icons, 48, kMinimumIconSize, Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon_x1.png", url.spec());

  url = FindBestMatchingIcon(icons, 96, kMinimumIconSize, Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon_x2.png", url.spec());

  url = FindBestMatchingIcon(icons, 144, kMinimumIconSize, Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon_x3.png", url.spec());
}

TEST_P(ManifestIconSelectorTest, FallbackToLargestIconLargerThanMinimum) {
  // When an icon of the correct size has not been found, we fall back to the
  // closest non-matching sizes. Make sure that the minimum passed is enforced.
  std::vector<gfx::Size> sizes_1_2;
  std::vector<gfx::Size> sizes_3;

  sizes_1_2.push_back(gfx::Size(width_to_height_ratio() * 47, 47));
  sizes_3.push_back(gfx::Size(width_to_height_ratio() * 95, 95));

  std::vector<blink::Manifest::ImageResource> icons;
  icons.push_back(
      CreateIcon("http://foo.com/icon_x1.png", "", sizes_1_2, Purpose::ANY));
  icons.push_back(
      CreateIcon("http://foo.com/icon_x2.png", "", sizes_1_2, Purpose::ANY));
  icons.push_back(
      CreateIcon("http://foo.com/icon_x3.png", "", sizes_3, Purpose::ANY));

  // Icon 3 should match.
  GURL url = FindBestMatchingIcon(icons, 1024, 48, Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon_x3.png", url.spec());

  // Nothing matches here as the minimum is 96.
  url = FindBestMatchingIcon(icons, 1024, 96, Purpose::ANY);
  EXPECT_TRUE(url.is_empty());
}

TEST_P(ManifestIconSelectorTest, IdealVeryCloseToMinimumMatches) {
  std::vector<gfx::Size> sizes;
  sizes.push_back(gfx::Size(width_to_height_ratio() * 2, 2));

  std::vector<blink::Manifest::ImageResource> icons;
  icons.push_back(
      CreateIcon("http://foo.com/icon_x1.png", "", sizes, Purpose::ANY));

  GURL url = FindBestMatchingIcon(icons, 2, 1, Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon_x1.png", url.spec());
}

TEST_P(ManifestIconSelectorTest, SizeVeryCloseToMinimumMatches) {
  std::vector<gfx::Size> sizes;
  sizes.push_back(gfx::Size(width_to_height_ratio() * 2, 2));

  std::vector<blink::Manifest::ImageResource> icons;
  icons.push_back(
      CreateIcon("http://foo.com/icon_x1.png", "", sizes, Purpose::ANY));

  GURL url = FindBestMatchingIcon(icons, 200, 1, Purpose::ANY);
  EXPECT_EQ("http://foo.com/icon_x1.png", url.spec());
}

TEST_P(ManifestIconSelectorTest, IconsWithInvalidDimensionsAreIgnored) {
  std::vector<gfx::Size> sizes;
  if (selects_square_only()) {
    // Square selector should ignore non-square icons.
    sizes.push_back(gfx::Size(1024, 1023));
  } else {
    // Landscape selector should ignore icons with improper width/height ratio.
    sizes.push_back(gfx::Size((kMaxWidthToHeightRatio + 1) * 1023, 1023));
    // Landscape selector should ignore portrait icons.
    sizes.push_back(gfx::Size(1023, 1024));
  }

  std::vector<blink::Manifest::ImageResource> icons;
  icons.push_back(
      CreateIcon("http://foo.com/icon.png", "", sizes, Purpose::ANY));

  GURL url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                                  Purpose::ANY);
  EXPECT_TRUE(url.is_empty());
}

TEST_P(ManifestIconSelectorTest, ClosestIconToIdeal) {
  // Ensure ManifestIconSelector::FindBestMatchingSquareIcon selects the closest
  // icon to the ideal size when presented with a number of options.
  int very_small = kIdealIconSize / 4;
  int small_size = kIdealIconSize / 2;
  int bit_small = kIdealIconSize - 1;
  int bit_big = kIdealIconSize + 1;
  int big = kIdealIconSize * 2;
  int very_big = kIdealIconSize * 4;

  // (very_small, bit_small) => bit_small
  {
    std::vector<gfx::Size> sizes_1;
    sizes_1.push_back(
        gfx::Size(width_to_height_ratio() * very_small, very_small));

    std::vector<gfx::Size> sizes_2;
    sizes_2.push_back(
        gfx::Size(width_to_height_ratio() * bit_small, bit_small));

    std::vector<blink::Manifest::ImageResource> icons;
    icons.push_back(
        CreateIcon("http://foo.com/icon_no.png", "", sizes_1, Purpose::ANY));
    icons.push_back(
        CreateIcon("http://foo.com/icon.png", "", sizes_2, Purpose::ANY));

    GURL url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                                    Purpose::ANY);
    EXPECT_EQ("http://foo.com/icon.png", url.spec());
  }

  // (very_small, bit_small, small_size) => bit_small
  {
    std::vector<gfx::Size> sizes_1;
    sizes_1.push_back(
        gfx::Size(width_to_height_ratio() * very_small, very_small));

    std::vector<gfx::Size> sizes_2;
    sizes_2.push_back(
        gfx::Size(width_to_height_ratio() * bit_small, bit_small));

    std::vector<gfx::Size> sizes_3;
    sizes_3.push_back(
        gfx::Size(width_to_height_ratio() * small_size, small_size));

    std::vector<blink::Manifest::ImageResource> icons;
    icons.push_back(
        CreateIcon("http://foo.com/icon_no_1.png", "", sizes_1, Purpose::ANY));
    icons.push_back(
        CreateIcon("http://foo.com/icon.png", "", sizes_2, Purpose::ANY));
    icons.push_back(
        CreateIcon("http://foo.com/icon_no_2.png", "", sizes_3, Purpose::ANY));

    GURL url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                                    Purpose::ANY);
    EXPECT_EQ("http://foo.com/icon.png", url.spec());
  }

  // (very_big, big) => big
  {
    std::vector<gfx::Size> sizes_1;
    sizes_1.push_back(gfx::Size(width_to_height_ratio() * very_big, very_big));

    std::vector<gfx::Size> sizes_2;
    sizes_2.push_back(gfx::Size(width_to_height_ratio() * big, big));

    std::vector<blink::Manifest::ImageResource> icons;
    icons.push_back(
        CreateIcon("http://foo.com/icon_no.png", "", sizes_1, Purpose::ANY));
    icons.push_back(
        CreateIcon("http://foo.com/icon.png", "", sizes_2, Purpose::ANY));

    GURL url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                                    Purpose::ANY);
    EXPECT_EQ("http://foo.com/icon.png", url.spec());
  }

  // (very_big, big, bit_big) => bit_big
  {
    std::vector<gfx::Size> sizes_1;
    sizes_1.push_back(gfx::Size(width_to_height_ratio() * very_big, very_big));

    std::vector<gfx::Size> sizes_2;
    sizes_2.push_back(gfx::Size(width_to_height_ratio() * big, big));

    std::vector<gfx::Size> sizes_3;
    sizes_3.push_back(gfx::Size(width_to_height_ratio() * bit_big, bit_big));

    std::vector<blink::Manifest::ImageResource> icons;
    icons.push_back(
        CreateIcon("http://foo.com/icon_no.png", "", sizes_1, Purpose::ANY));
    icons.push_back(
        CreateIcon("http://foo.com/icon_no.png", "", sizes_2, Purpose::ANY));
    icons.push_back(
        CreateIcon("http://foo.com/icon.png", "", sizes_3, Purpose::ANY));

    GURL url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                                    Purpose::ANY);
    EXPECT_EQ("http://foo.com/icon.png", url.spec());
  }

  // (bit_small, very_big) => very_big
  {
    std::vector<gfx::Size> sizes_1;
    sizes_1.push_back(
        gfx::Size(width_to_height_ratio() * bit_small, bit_small));

    std::vector<gfx::Size> sizes_2;
    sizes_2.push_back(gfx::Size(width_to_height_ratio() * very_big, very_big));

    std::vector<blink::Manifest::ImageResource> icons;
    icons.push_back(
        CreateIcon("http://foo.com/icon_no.png", "", sizes_1, Purpose::ANY));
    icons.push_back(
        CreateIcon("http://foo.com/icon.png", "", sizes_2, Purpose::ANY));

    GURL url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                                    Purpose::ANY);
    EXPECT_EQ("http://foo.com/icon.png", url.spec());
  }

  // (bit_small, bit_big) => bit_big
  {
    std::vector<gfx::Size> sizes_1;
    sizes_1.push_back(
        gfx::Size(width_to_height_ratio() * bit_small, bit_small));

    std::vector<gfx::Size> sizes_2;
    sizes_2.push_back(gfx::Size(width_to_height_ratio() * bit_big, bit_big));

    std::vector<blink::Manifest::ImageResource> icons;
    icons.push_back(
        CreateIcon("http://foo.com/icon_no.png", "", sizes_1, Purpose::ANY));
    icons.push_back(
        CreateIcon("http://foo.com/icon.png", "", sizes_2, Purpose::ANY));

    GURL url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                                    Purpose::ANY);
    EXPECT_EQ("http://foo.com/icon.png", url.spec());
  }
}

TEST_P(ManifestIconSelectorTest, UseAnyIfNoIdealSize) {
  // 'any' (ie. gfx::Size(0,0)) should be used if there is no icon of a
  // ideal size.

  // Icon with 'any' and icon with ideal size => ideal size is chosen.
  {
    std::vector<gfx::Size> sizes_1;
    sizes_1.push_back(
        gfx::Size(width_to_height_ratio() * kIdealIconSize, kIdealIconSize));
    std::vector<gfx::Size> sizes_2;
    sizes_2.push_back(gfx::Size(0, 0));

    std::vector<blink::Manifest::ImageResource> icons;
    icons.push_back(
        CreateIcon("http://foo.com/icon.png", "", sizes_1, Purpose::ANY));
    icons.push_back(
        CreateIcon("http://foo.com/icon_no.png", "", sizes_2, Purpose::ANY));

    GURL url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                                    Purpose::ANY);
    EXPECT_EQ("http://foo.com/icon.png", url.spec());
  }

  // Icon with 'any' and icon larger than ideal size => any is chosen.
  {
    std::vector<gfx::Size> sizes_1;
    sizes_1.push_back(gfx::Size(width_to_height_ratio() * (kIdealIconSize + 1),
                                kIdealIconSize + 1));
    std::vector<gfx::Size> sizes_2;
    sizes_2.push_back(gfx::Size(0, 0));

    std::vector<blink::Manifest::ImageResource> icons;
    icons.push_back(
        CreateIcon("http://foo.com/icon_no.png", "", sizes_1, Purpose::ANY));
    icons.push_back(
        CreateIcon("http://foo.com/icon.png", "", sizes_2, Purpose::ANY));

    GURL url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                                    Purpose::ANY);
    EXPECT_EQ("http://foo.com/icon.png", url.spec());
  }

  // Multiple icons with 'any' => the last one is chosen.
  {
    std::vector<gfx::Size> sizes;
    sizes.push_back(gfx::Size(0, 0));

    std::vector<blink::Manifest::ImageResource> icons;
    icons.push_back(
        CreateIcon("http://foo.com/icon_no1.png", "", sizes, Purpose::ANY));
    icons.push_back(
        CreateIcon("http://foo.com/icon_no2.png", "", sizes, Purpose::ANY));
    icons.push_back(
        CreateIcon("http://foo.com/icon.png", "", sizes, Purpose::ANY));

    GURL url = FindBestMatchingIcon(icons, kIdealIconSize * 3, kMinimumIconSize,
                                    Purpose::ANY);
    EXPECT_EQ("http://foo.com/icon.png", url.spec());
  }

  // Multiple icons with ideal size => the last one is chosen.
  {
    std::vector<gfx::Size> sizes_1;
    sizes_1.push_back(
        gfx::Size(width_to_height_ratio() * kIdealIconSize, kIdealIconSize));
    std::vector<gfx::Size> sizes_2;
    sizes_2.push_back(
        gfx::Size(width_to_height_ratio() * kIdealIconSize, kIdealIconSize));

    std::vector<blink::Manifest::ImageResource> icons;
    icons.push_back(
        CreateIcon("http://foo.com/icon.png", "", sizes_1, Purpose::ANY));
    icons.push_back(
        CreateIcon("http://foo.com/icon_no.png", "", sizes_2, Purpose::ANY));

    GURL url = FindBestMatchingIcon(icons, kIdealIconSize, kMinimumIconSize,
                                    Purpose::ANY);
    EXPECT_EQ("http://foo.com/icon_no.png", url.spec());
  }
}

INSTANTIATE_TEST_SUITE_P(All,
                         ManifestIconSelectorTest,
                         ::testing::Bool());

}  // namespace blink

"""

```