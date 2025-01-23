Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Initial Reading and Goal Identification:**

First, I read through the code to get a general understanding. The filename `input_file_parsers.cc` and the included headers like `base/json/json_reader.h`, `net/tools/transport_security_state_generator/pinset.h`, etc., strongly suggest this file is responsible for parsing input files used by the `transport_security_state_generator` tool. The goal is to process configuration data related to HSTS (HTTP Strict Transport Security) and public key pinning.

**2. Identifying Key Functions and Their Roles:**

I started identifying the main functions:

* `ParseCertificatesFile`: This function's name and the constants like `kStartOfCert`, `kStartOfPublicKey` clearly indicate it parses a file containing certificates or public keys, and associates them with names. The logic of state transitions within the function reinforces this.
* `ParseJSON`: This function's name and the use of `base::JSONReader` tell us it parses JSON files. The keys like `kNameJSONKey`, `kIncludeSubdomainsJSONKey`, `kPinsJSONKey` suggest it deals with HSTS and pinning configurations.

**3. Understanding Data Structures and Relationships:**

I looked at the parameters these functions take and the data structures they manipulate:

* `Pinsets* pinsets`:  This pointer suggests a central repository for storing information about pinsets and the SPKI hashes associated with them.
* `base::Time* timestamp`:  Indicates the `ParseCertificatesFile` function also handles a timestamp.
* `TransportSecurityStateEntries* entries`: This pointer passed to `ParseJSON` implies a data structure (likely a `std::vector`) to store parsed HSTS entries.

The call to `pinsets->RegisterSPKIHash` in `ParseCertificatesFile` and the usage of `pins_map` to connect hostnames with pinsets in `ParseJSON` reveal how the two functions collaborate.

**4. Analyzing Individual Function Logic:**

* **`ParseCertificatesFile`:** I traced the state transitions based on the input lines. The handling of certificate boundaries (`-----BEGIN CERTIFICATE`, `-----END CERTIFICATE`), public key boundaries, and the "sha256/" prefix for direct hash input are crucial observations. The checks like `IsValidName` and `MatchCertificateName` are also important.
* **`ParseJSON`:** I focused on how the HSTS and pins JSON structures are processed. The validation of keys (`valid_hsts_keys`, `valid_pins_keys`), the iteration through the "entries" lists, and the handling of the "pinsets" list stood out. The logic for merging HSTS and pinning information based on hostname was also noted.

**5. Identifying Potential Connections to JavaScript (Specific Request):**

I considered where JavaScript might interact with this. HSTS and public key pinning are security mechanisms enforced by web browsers. Therefore, the *output* of this tool is likely used by Chromium's networking stack, which in turn affects how the browser handles websites.

* **No Direct JavaScript in the Parser:**  The code is C++. There's no direct JavaScript interaction within the *parsing* logic itself.
* **Impact on Browser Behavior:** The parsed data influences how Chromium (and thus its JavaScript engine) handles network requests. If a website has a preloaded HSTS entry, the browser will automatically use HTTPS. If it has pinned certificates, the browser will only trust connections using those specific certificates.

**6. Formulating Examples and Assumptions (Specific Request):**

To demonstrate logical reasoning, I created hypothetical input and output scenarios:

* **`ParseCertificatesFile`:** A simple example with a certificate block and how it would result in registering a specific SPKI hash. I also considered a timestamp scenario.
* **`ParseJSON`:**  An example showing how HSTS and pinning information in the JSON files would be combined into `TransportSecurityStateEntry` objects.

**7. Identifying User/Programming Errors (Specific Request):**

I thought about common mistakes users or developers might make:

* **`ParseCertificatesFile`:** Incorrect formatting of certificates, typos in names, missing timestamps.
* **`ParseJSON`:** Invalid JSON syntax, incorrect key names, missing required fields, inconsistent data types.

**8. Tracing User Operations (Specific Request):**

This requires understanding the context of the `transport_security_state_generator` tool. I reasoned that a developer working on Chromium's security features would be the primary user:

1. **Modifying Input Files:**  The developer would manually edit the HSTS and pins JSON files or the certificates file to add or update entries.
2. **Running the Generator Tool:** The developer would then run the `transport_security_state_generator` tool, providing the paths to these input files as arguments.
3. **Compilation and Integration:** The output of the generator (likely C++ source code) would be compiled into Chromium.
4. **Browser Behavior:** When a user browses to a website, Chromium's networking stack would use the generated data to enforce HSTS and pinning.

**9. Structuring the Answer:**

Finally, I organized the information into the requested categories: Functionality, Relationship to JavaScript, Logical Reasoning, User Errors, and User Operation/Debugging. I used clear and concise language, providing specific examples and explanations where necessary.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the low-level details of the C++ code. I realized the prompt also asked about the broader functionality and its relation to user behavior.
* I made sure to explicitly state the *indirect* relationship with JavaScript, as the parsing itself doesn't involve JavaScript.
* I refined the example inputs and outputs to be clear and illustrative.
* I considered different types of user errors, including both formatting issues and logical inconsistencies in the input data.
The C++ source code file `input_file_parsers.cc` located in the `net/tools/transport_security_state_generator` directory of the Chromium project is responsible for parsing input files used by the `transport_security_state_generator` tool. This tool is used to generate static data structures that are compiled into Chromium, defining the HSTS (HTTP Strict Transport Security) and HPKP (HTTP Public Key Pinning) policies for various websites.

Here's a breakdown of its functionality:

**1. Parsing Certificate Files (`ParseCertificatesFile` function):**

* **Purpose:** This function parses files containing certificate information (either full PEM-encoded certificates or just the Subject Public Key Info (SPKI) hashes) and associates them with symbolic names.
* **Input Format:** The file format is line-based:
    * **Comments:** Lines starting with `#` are ignored.
    * **Names:** A line containing a valid C++ identifier (starting with an uppercase letter, followed by alphanumeric characters or underscores) acts as the name for the following certificate or SPKI hash.
    * **SPKI Hashes:** Lines starting with "sha256/" followed by a base64-encoded SHA256 hash of the SPKI.
    * **Certificates:** PEM-encoded certificates enclosed by `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----`.
    * **Public Keys:** PEM-encoded public keys enclosed by `-----BEGIN PUBLIC KEY-----` and `-----END PUBLIC KEY-----`.
    * **Timestamp:** A line containing "PinsListTimestamp" followed by a number representing the Unix epoch timestamp for the pins list.
* **Output:** It populates a `Pinsets` object with the parsed SPKI hashes, associating them with the provided names. It also extracts the timestamp of the pins list.
* **Logic:**
    * It uses a state machine to track whether it's currently parsing a name, a certificate, or a public key.
    * It validates the format of names and SPKI hashes.
    * It uses OpenSSL functions to parse certificates and extract SPKI hashes.
    * It attempts to match the symbolic name with parts of the certificate's subject name for sanity checks.

**2. Parsing JSON Files (`ParseJSON` function):**

* **Purpose:** This function parses two JSON files: one containing HSTS preload entries and another containing HPKP pinning information.
* **Input Format:**
    * **HSTS JSON:** Contains a dictionary with an "entries" key, whose value is a list of dictionaries. Each dictionary represents an HSTS entry with keys like "name" (hostname), "policy", "include_subdomains", and "mode" ("force-https").
    * **Pins JSON:** Contains a dictionary with "entries" and "pinsets" keys.
        * "entries" is a list of dictionaries, each with "name" (hostname), "include_subdomains", and "pins" (the name of a pinset).
        * "pinsets" is a list of dictionaries, each defining a pinset with "name", optionally "report_uri", "static_spki_hashes", and "bad_static_spki_hashes".
* **Output:** It populates a `TransportSecurityStateEntries` object (likely a `std::vector` of `TransportSecurityStateEntry` objects) with the parsed HSTS and HPKP entries. It also updates the `Pinsets` object with information from the pins JSON.
* **Logic:**
    * It uses `base::JSONReader` to parse the JSON files.
    * It iterates through the "entries" lists in both JSON files.
    * It validates the keys and values in each entry according to predefined valid keys and policies.
    * It links HSTS entries with corresponding pinsets based on the hostname.
    * It creates `TransportSecurityStateEntry` objects containing the parsed information.
    * It registers pinsets and their associated SPKI hashes (both good and bad) in the `Pinsets` object.

**Relationship to JavaScript:**

This C++ code itself does not directly interact with JavaScript code at runtime. However, the *output* of the `transport_security_state_generator` tool, which this code contributes to, directly affects how Chromium's networking stack (which is part of the browser environment where JavaScript runs) handles HTTPS connections.

* **HSTS Preloading:** The parsed HSTS entries are compiled into Chromium. When a user navigates to a website with a preloaded HSTS entry, the browser automatically upgrades the connection to HTTPS even if the user typed `http://`. This is a security feature that prevents man-in-the-middle attacks. JavaScript code running on such websites benefits from this secure connection.
* **HTTP Public Key Pinning (HPKP):**  The parsed HPKP entries specify the expected public keys (or hashes of the SPKI) for certain websites. When the browser connects to such a website, it verifies that the server's certificate chain includes one of the pinned public keys. If not, the connection is refused, protecting against compromised Certificate Authorities. JavaScript on pinned websites relies on this security mechanism.

**Example of Interaction (Indirect):**

1. **Input JSON:**
   ```json
   // hsts.json
   {
     "entries": [
       { "name": "example.com", "policy": "google", "include_subdomains": false, "mode": "force-https" }
     ]
   }

   // pins.json
   {
     "entries": [
       { "name": "example.com", "include_subdomains": false, "pins": "example_com_pinset" }
     ],
     "pinsets": [
       {
         "name": "example_com_pinset",
         "static_spki_hashes": ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
       }
     ]
   }
   ```

2. **`input_file_parsers.cc` Processing:** The `ParseJSON` function would parse these files, creating a `TransportSecurityStateEntry` for "example.com" with `force_https = true` and `pinset = "example_com_pinset"`. The `Pinsets` object would contain a pinset named "example_com_pinset" with the specified SPKI hash.

3. **Code Generation (by the tool):** The `transport_security_state_generator` tool would then generate C++ code based on this parsed data, which would be compiled into Chromium.

4. **Browser Behavior (JavaScript Context):** When a user navigates to `http://example.com`, Chromium's networking stack, using the preloaded data, will automatically redirect the browser to `https://example.com`. Any JavaScript code on `example.com` will now be running over a secure HTTPS connection, enforced by the preloaded HSTS policy. Additionally, the browser will enforce the public key pinning policy when connecting to `example.com`.

**Logical Reasoning (with Assumptions):**

**Assumption for `ParseCertificatesFile`:**

* **Input:**
  ```
  MyGreatCert
  -----BEGIN CERTIFICATE-----
  MIIC8jCCAdoCCQC/o9E7k92Q4TANBgkqhkiG9w0BAQsFADCBjjELMAkGA1UEBhMC
  VVMxCzAJBgNVBAgTAkNBMRAwDgYDVQQHEwdNb3VudGFpbjEQMA4GA1UEChMHQWNt
  ZSBDbzERMA8GA1UECxMIU2VjdXJpdHkxEjAQBgNVBAMTCmexampleLmNvbTAeFw0y
  MzEwMjYxNzQ1MzNaFw0yNDExMjUxNzQ1MzNaMIGCMQswCQYDVQQGEwJVUzELMAkG
  A1UECBMCQ0ExETMBEgYDVQQHEwpNb3VudGFpbiBWaWV3MQ4wDAYDVQQKEwVBbWNu
  ZTEQMA4GA1UECxMHTmV0d29yazEQMA4GA1UEAxMTd3d3LmV4YW1wbGUuY29tMIIB
  IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1nLg1jP0VbJjK6iN/r9b0T6
  ... (rest of the certificate) ...
  -----END CERTIFICATE-----
  ```
* **Output (in `Pinsets` object):** A SPKI hash calculated from the provided certificate would be registered under the name "MyGreatCert". The `MatchCertificateName` function would likely return `true` because "MyGreatCert" is a prefix of the first word of the subject name "example.com".

**Assumption for `ParseJSON`:**

* **Input (snippets from `hsts.json` and `pins.json` as shown in the "Relationship to JavaScript" example):**
* **Output (`TransportSecurityStateEntries`):** A `TransportSecurityStateEntry` object would be created with:
    * `hostname = "example.com"`
    * `force_https = true`
    * `include_subdomains = false`
    * `pinset = "example_com_pinset"`
    * `hpkp_include_subdomains = false` (assuming not specified in the pins entry).

**User or Programming Common Usage Errors:**

**`ParseCertificatesFile`:**

* **Incorrect Certificate Formatting:**  Forgetting the `-----BEGIN/END CERTIFICATE-----` markers, or having extra whitespace or characters within the PEM block.
  ```
  # Error: Missing BEGIN marker
  MyBadCert
  MIIC8jCCAdoCCQC/o9E7k92Q4TANBgkqhkiG9w0BAQsFADCBjjELMAkGA1UEBhMC
  ...
  ```
* **Typos in Names:**  Using names that are not valid C++ identifiers or that don't reasonably match the certificate subject.
  ```
  my-great-cert # Error: Hyphens are not allowed in identifiers
  -----BEGIN CERTIFICATE-----
  ...
  ```
* **Missing Timestamp:** Forgetting to include the `PinsListTimestamp` and its value in the file. This would lead to a parsing error.
* **Incorrect SPKI Hash Format:** Providing an SPKI hash that doesn't start with "sha256/" or is not a valid base64 string.

**`ParseJSON`:**

* **Invalid JSON Syntax:**  Missing commas, brackets, or quotes, leading to parsing failures by `base::JSONReader`.
* **Incorrect Key Names:** Using typos in the JSON keys (e.g., `"nam"` instead of `"name"`).
* **Missing Required Fields:** Omitting mandatory fields like "name" or "policy" in the HSTS entries.
* **Incorrect Data Types:** Providing a string when a boolean is expected (e.g., `"include_subdomains": "false"` instead of `"include_subdomains": false`).
* **Referring to Non-existent Pinsets:**  Specifying a pinset name in the "pins" entry that is not defined in the "pinsets" section.
* **Duplicate Hostnames in JSON:** Having multiple entries for the same hostname in either the HSTS or pins JSON.

**User Operation Steps to Reach This Code (as Debugging Clues):**

1. **Developer Modifies Input Files:** A Chromium developer or someone contributing to the project needs to update the HSTS preload list or the HPKP pinsets. They would manually edit the `transport_security_state_static.json` (for HSTS) and likely a separate pins JSON file (the exact file name might vary depending on the Chromium configuration). They might also update a file containing certificate information for defining pinset hashes.

2. **Running the Generator Tool:** The developer would then run the `transport_security_state_generator` tool. This tool takes the paths to these input files as command-line arguments. The command might look something like:

   ```bash
   ./transport_security_state_generator \
     --hsts-input=net/http/transport_security_state_static.json \
     --pins-input=net/http/transport_security_state_pins.json \
     --certs-input=net/tools/transport_security_state_generator/pins/pinned_certs.txt \
     --output-hsts-c=net/http/transport_security_state_static.h \
     --output-pins-c=net/http/transport_security_state_static_pins.h
   ```

3. **Parsing by `input_file_parsers.cc`:**  The `transport_security_state_generator` tool would then use the functions in `input_file_parsers.cc` (specifically `ParseJSON` and `ParseCertificatesFile`) to read and parse the contents of the specified input files.

4. **Error Reporting (If Errors Occur):** If there are errors in the input files (as described in the "Usage Errors" section), the logging statements within `input_file_parsers.cc` (using `LOG(ERROR)`) would be triggered, and the tool would likely exit with an error message, indicating the line number and nature of the problem in the input file.

5. **Debugging:** If a developer encounters an error message from the generator tool related to parsing, they would:
   * **Check the input files:** Verify the JSON syntax, key names, data types, certificate formatting, and naming conventions in the input files.
   * **Examine the error message:** The error message usually points to the specific file and sometimes even the line number where the parsing error occurred.
   * **Step through the code (if necessary):** If the error is complex, a developer might need to use a debugger to step through the `ParseJSON` or `ParseCertificatesFile` functions in `input_file_parsers.cc` to understand exactly where the parsing logic is failing and what the values of variables are at that point. They would set breakpoints and inspect the data being read from the input files.

In essence, `input_file_parsers.cc` is a crucial component in the process of defining and updating the security policies that Chromium enforces for web browsing. It acts as the bridge between human-readable configuration files and the internal data structures used by the browser.

### 提示词
```
这是目录为net/tools/transport_security_state_generator/input_file_parsers.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/transport_security_state_generator/input_file_parsers.h"

#include <set>
#include <sstream>
#include <string_view>
#include <vector>

#include "base/containers/contains.h"
#include "base/containers/fixed_flat_set.h"
#include "base/json/json_reader.h"
#include "base/logging.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/tools/transport_security_state_generator/cert_util.h"
#include "net/tools/transport_security_state_generator/pinset.h"
#include "net/tools/transport_security_state_generator/pinsets.h"
#include "net/tools/transport_security_state_generator/spki_hash.h"
#include "third_party/boringssl/src/include/openssl/x509v3.h"

namespace net::transport_security_state {

namespace {

bool IsImportantWordInCertificateName(std::string_view name) {
  const char* const important_words[] = {"Universal", "Global", "EV", "G1",
                                         "G2",        "G3",     "G4", "G5"};
  for (auto* important_word : important_words) {
    if (name == important_word) {
      return true;
    }
  }
  return false;
}

// Strips all characters not matched by the RegEx [A-Za-z0-9_] from |name| and
// returns the result.
std::string FilterName(std::string_view name) {
  std::string filtered;
  for (const char& character : name) {
    if ((character >= '0' && character <= '9') ||
        (character >= 'a' && character <= 'z') ||
        (character >= 'A' && character <= 'Z') || character == '_') {
      filtered += character;
    }
  }
  return base::ToLowerASCII(filtered);
}

// Returns true if |pin_name| is a reasonable match for the certificate name
// |name|.
bool MatchCertificateName(std::string_view name, std::string_view pin_name) {
  std::vector<std::string_view> words = base::SplitStringPiece(
      name, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (words.empty()) {
    LOG(ERROR) << "No words in certificate name for pin " << pin_name;
    return false;
  }
  std::string_view first_word = words[0];

  if (first_word.ends_with(",")) {
    first_word = first_word.substr(0, first_word.size() - 1);
  }

  if (first_word.starts_with("*.")) {
    first_word = first_word.substr(2, first_word.size() - 2);
  }

  size_t pos = first_word.find('.');
  if (pos != std::string::npos) {
    first_word = first_word.substr(0, first_word.size() - pos);
  }

  pos = first_word.find('-');
  if (pos != std::string::npos) {
    first_word = first_word.substr(0, first_word.size() - pos);
  }

  if (first_word.empty()) {
    LOG(ERROR) << "First word of certificate name (" << name << ") is empty";
    return false;
  }

  std::string filtered_word = FilterName(first_word);
  first_word = filtered_word;
  if (!base::EqualsCaseInsensitiveASCII(pin_name.substr(0, first_word.size()),
                                        first_word)) {
    LOG(ERROR) << "The first word of the certificate name (" << first_word
               << ") isn't a prefix of the variable name (" << pin_name << ")";
    return false;
  }

  for (size_t i = 0; i < words.size(); ++i) {
    std::string_view word = words[i];
    if (word == "Class" && (i + 1) < words.size()) {
      std::string class_name = base::StrCat({word, words[i + 1]});

      pos = pin_name.find(class_name);
      if (pos == std::string::npos) {
        LOG(ERROR)
            << "Certficate class specification doesn't appear in the variable "
               "name ("
            << pin_name << ")";
        return false;
      }
    } else if (word.size() == 1 && word[0] >= '0' && word[0] <= '9') {
      pos = pin_name.find(word);
      if (pos == std::string::npos) {
        LOG(ERROR) << "Number doesn't appear in the certificate variable name ("
                   << pin_name << ")";
        return false;
      }
    } else if (IsImportantWordInCertificateName(word)) {
      pos = pin_name.find(word);
      if (pos == std::string::npos) {
        LOG(ERROR) << std::string(word) +
                          " doesn't appear in the certificate variable name ("
                   << pin_name << ")";
        return false;
      }
    }
  }

  return true;
}

// Returns true iff |candidate| is not empty, the first character is in the
// range A-Z, and the remaining characters are in the ranges a-Z, 0-9, or '_'.
bool IsValidName(std::string_view candidate) {
  if (candidate.empty() || candidate[0] < 'A' || candidate[0] > 'Z') {
    return false;
  }

  bool isValid = true;
  for (const char& character : candidate) {
    isValid = (character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'z') ||
              (character >= 'A' && character <= 'Z') || character == '_';
    if (!isValid) {
      return false;
    }
  }
  return true;
}

static const char kStartOfCert[] = "-----BEGIN CERTIFICATE";
static const char kStartOfPublicKey[] = "-----BEGIN PUBLIC KEY";
static const char kEndOfCert[] = "-----END CERTIFICATE";
static const char kEndOfPublicKey[] = "-----END PUBLIC KEY";
static const char kStartOfSHA256[] = "sha256/";

enum class CertificateParserState {
  PRE_NAME,
  POST_NAME,
  IN_CERTIFICATE,
  IN_PUBLIC_KEY,
  PRE_TIMESTAMP,
};

// Valid keys for entries in the input JSON. These fields will be included in
// the output.
static constexpr char kNameJSONKey[] = "name";
static constexpr char kIncludeSubdomainsJSONKey[] = "include_subdomains";
static constexpr char kModeJSONKey[] = "mode";
static constexpr char kPinsJSONKey[] = "pins";
static constexpr char kTimestampName[] = "PinsListTimestamp";

// Additional valid keys for entries in the input JSON that will not be included
// in the output and contain metadata (e.g., for list maintenance).
static constexpr char kPolicyJSONKey[] = "policy";

}  // namespace

bool ParseCertificatesFile(std::string_view certs_input,
                           Pinsets* pinsets,
                           base::Time* timestamp) {
  if (certs_input.find("\r\n") != std::string_view::npos) {
    LOG(ERROR) << "CRLF line-endings found in the pins file. All files must "
                  "use LF (unix style) line-endings.";
    return false;
  }

  CertificateParserState current_state = CertificateParserState::PRE_NAME;
  bool timestamp_parsed = false;

  const base::CompareCase& compare_mode = base::CompareCase::INSENSITIVE_ASCII;
  std::string name;
  std::string buffer;
  std::string subject_name;
  bssl::UniquePtr<X509> certificate;
  SPKIHash hash;

  for (std::string_view line : SplitStringPiece(
           certs_input, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL)) {
    if (!line.empty() && line[0] == '#') {
      continue;
    }

    if (line.empty() && current_state == CertificateParserState::PRE_NAME) {
      continue;
    }

    switch (current_state) {
      case CertificateParserState::PRE_NAME:
        if (line == kTimestampName) {
          current_state = CertificateParserState::PRE_TIMESTAMP;
          break;
        }
        if (!IsValidName(line)) {
          LOG(ERROR) << "Invalid name in pins file: " << line;
          return false;
        }
        name = std::string(line);
        current_state = CertificateParserState::POST_NAME;
        break;
      case CertificateParserState::POST_NAME:
        if (base::StartsWith(line, kStartOfSHA256, compare_mode)) {
          if (!hash.FromString(line)) {
            LOG(ERROR) << "Invalid hash value in pins file for " << name;
            return false;
          }

          pinsets->RegisterSPKIHash(name, hash);
          current_state = CertificateParserState::PRE_NAME;
        } else if (base::StartsWith(line, kStartOfCert, compare_mode)) {
          buffer = std::string(line) + '\n';
          current_state = CertificateParserState::IN_CERTIFICATE;
        } else if (base::StartsWith(line, kStartOfPublicKey, compare_mode)) {
          buffer = std::string(line) + '\n';
          current_state = CertificateParserState::IN_PUBLIC_KEY;
        } else {
          LOG(ERROR) << "Invalid value in pins file for " << name;
          return false;
        }
        break;
      case CertificateParserState::IN_CERTIFICATE:
        buffer += std::string(line) + '\n';
        if (!base::StartsWith(line, kEndOfCert, compare_mode)) {
          continue;
        }

        certificate = GetX509CertificateFromPEM(buffer);
        if (!certificate) {
          LOG(ERROR) << "Could not parse certificate " << name;
          return false;
        }

        if (!CalculateSPKIHashFromCertificate(certificate.get(), &hash)) {
          LOG(ERROR) << "Could not extract SPKI from certificate " << name;
          return false;
        }

        if (!ExtractSubjectNameFromCertificate(certificate.get(),
                                               &subject_name)) {
          LOG(ERROR) << "Could not extract name from certificate " << name;
          return false;
        }

        if (!MatchCertificateName(subject_name, name)) {
          LOG(ERROR) << name << " is not a reasonable name for "
                     << subject_name;
          return false;
        }

        pinsets->RegisterSPKIHash(name, hash);
        current_state = CertificateParserState::PRE_NAME;
        break;
      case CertificateParserState::IN_PUBLIC_KEY:
        buffer += std::string(line) + '\n';
        if (!base::StartsWith(line, kEndOfPublicKey, compare_mode)) {
          continue;
        }

        if (!CalculateSPKIHashFromKey(buffer, &hash)) {
          LOG(ERROR) << "Could not parse the public key for " << name;
          return false;
        }

        pinsets->RegisterSPKIHash(name, hash);
        current_state = CertificateParserState::PRE_NAME;
        break;
      case CertificateParserState::PRE_TIMESTAMP:
        uint64_t timestamp_epoch;
        if (!base::StringToUint64(line, &timestamp_epoch) ||
            !base::IsValueInRangeForNumericType<time_t>(timestamp_epoch)) {
          LOG(ERROR) << "Could not parse the timestamp value";
          return false;
        }
        *timestamp = base::Time::FromTimeT(timestamp_epoch);
        if (timestamp_parsed) {
          LOG(ERROR) << "File contains multiple timestamps";
          return false;
        }
        timestamp_parsed = true;
        current_state = CertificateParserState::PRE_NAME;
        break;
      default:
        DCHECK(false) << "Unknown parser state";
    }
  }

  if (!timestamp_parsed) {
    LOG(ERROR) << "Timestamp is missing";
    return false;
  }
  return true;
}

bool ParseJSON(std::string_view hsts_json,
               std::string_view pins_json,
               TransportSecurityStateEntries* entries,
               Pinsets* pinsets) {
  static constexpr auto valid_hsts_keys =
      base::MakeFixedFlatSet<std::string_view>({
          kNameJSONKey,
          kPolicyJSONKey,
          kIncludeSubdomainsJSONKey,
          kModeJSONKey,
          kPinsJSONKey,
      });

  static constexpr auto valid_pins_keys =
      base::MakeFixedFlatSet<std::string_view>({
          kNameJSONKey,
          kIncludeSubdomainsJSONKey,
          kPinsJSONKey,
      });

  // See the comments in net/http/transport_security_state_static.json for more
  // info on these policies.
  std::set<std::string> valid_policies = {
      "test",        "public-suffix", "google",      "custom",
      "bulk-legacy", "bulk-18-weeks", "bulk-1-year", "public-suffix-requested"};

  std::optional<base::Value> hsts_value = base::JSONReader::Read(hsts_json);
  if (!hsts_value.has_value() || !hsts_value->is_dict()) {
    LOG(ERROR) << "Could not parse the input HSTS JSON file";
    return false;
  }

  std::optional<base::Value> pins_value = base::JSONReader::Read(pins_json);
  if (!pins_value.has_value()) {
    LOG(ERROR) << "Could not parse the input pins JSON file";
    return false;
  }
  base::Value::Dict* pins_dict = pins_value->GetIfDict();
  if (!pins_dict) {
    LOG(ERROR) << "Input pins JSON file does not contain a dictionary";
    return false;
  }

  const base::Value::List* pinning_entries_list =
      pins_dict->FindList("entries");
  if (!pinning_entries_list) {
    LOG(ERROR) << "Could not parse the entries in the input pins JSON";
    return false;
  }
  std::map<std::string, std::pair<std::string, bool>> pins_map;
  for (size_t i = 0; i < pinning_entries_list->size(); ++i) {
    const base::Value::Dict* parsed = (*pinning_entries_list)[i].GetIfDict();
    if (!parsed) {
      LOG(ERROR) << "Could not parse entry " << base::NumberToString(i)
                 << " in the input pins JSON";
      return false;
    }
    const std::string* maybe_hostname = parsed->FindString(kNameJSONKey);
    if (!maybe_hostname) {
      LOG(ERROR) << "Could not extract the hostname for entry "
                 << base::NumberToString(i) << " from the input pins JSON";
      return false;
    }

    if (maybe_hostname->empty()) {
      LOG(ERROR) << "The hostname for entry " << base::NumberToString(i)
                 << " is empty";
      return false;
    }

    for (auto entry_value : *parsed) {
      if (!base::Contains(valid_pins_keys, entry_value.first)) {
        LOG(ERROR) << "The entry for " << *maybe_hostname
                   << " contains an unknown " << entry_value.first << " field";
        return false;
      }
    }

    const std::string* maybe_pinset = parsed->FindString(kPinsJSONKey);
    if (!maybe_pinset) {
      LOG(ERROR) << "Could not extract the pinset for entry "
                 << base::NumberToString(i) << " from the input pins JSON";
      return false;
    }

    if (pins_map.find(*maybe_hostname) != pins_map.end()) {
      LOG(ERROR) << *maybe_hostname
                 << " has duplicate entries in the input pins JSON";
      return false;
    }

    pins_map[*maybe_hostname] =
        std::pair(*maybe_pinset,
                  parsed->FindBool(kIncludeSubdomainsJSONKey).value_or(false));
  }

  const base::Value::List* preload_entries_list =
      hsts_value->GetDict().FindList("entries");
  if (!preload_entries_list) {
    LOG(ERROR) << "Could not parse the entries in the input HSTS JSON";
    return false;
  }

  for (size_t i = 0; i < preload_entries_list->size(); ++i) {
    const base::Value::Dict* parsed = (*preload_entries_list)[i].GetIfDict();
    if (!parsed) {
      LOG(ERROR) << "Could not parse entry " << base::NumberToString(i)
                 << " in the input HSTS JSON";
      return false;
    }

    auto entry = std::make_unique<TransportSecurityStateEntry>();
    const std::string* maybe_hostname = parsed->FindString(kNameJSONKey);
    if (!maybe_hostname) {
      LOG(ERROR) << "Could not extract the hostname for entry "
                 << base::NumberToString(i) << " from the input HSTS JSON";
      return false;
    }
    entry->hostname = *maybe_hostname;

    if (entry->hostname.empty()) {
      LOG(ERROR) << "The hostname for entry " << base::NumberToString(i)
                 << " is empty";
      return false;
    }

    for (auto entry_value : *parsed) {
      if (!base::Contains(valid_hsts_keys, entry_value.first)) {
        LOG(ERROR) << "The entry for " << entry->hostname
                   << " contains an unknown " << entry_value.first << " field";
        return false;
      }
    }

    const std::string* policy = parsed->FindString(kPolicyJSONKey);
    if (!policy || !base::Contains(valid_policies, *policy)) {
      LOG(ERROR) << "The entry for " << entry->hostname
                 << " does not have a valid policy";
      return false;
    }

    const std::string* maybe_mode = parsed->FindString(kModeJSONKey);
    std::string mode = maybe_mode ? *maybe_mode : std::string();
    entry->force_https = false;
    if (mode == "force-https") {
      entry->force_https = true;
    } else if (!mode.empty()) {
      LOG(ERROR) << "An unknown mode is set for entry " << entry->hostname;
      return false;
    }

    entry->include_subdomains =
        parsed->FindBool(kIncludeSubdomainsJSONKey).value_or(false);

    auto pins_it = pins_map.find(entry->hostname);
    if (pins_it != pins_map.end()) {
      entry->pinset = pins_it->second.first;
      entry->hpkp_include_subdomains = pins_it->second.second;
      pins_map.erase(entry->hostname);
    }

    entries->push_back(std::move(entry));
  }

  // Any remaining entries in pins_map have pinning information, but are not
  // HSTS preloaded.
  for (auto const& pins_entry : pins_map) {
    auto entry = std::make_unique<TransportSecurityStateEntry>();
    entry->hostname = pins_entry.first;
    entry->force_https = false;
    entry->pinset = pins_entry.second.first;
    entry->hpkp_include_subdomains = pins_entry.second.second;
    entries->push_back(std::move(entry));
  }

  base::Value::List* pinsets_list = pins_dict->FindList("pinsets");
  if (!pinsets_list) {
    LOG(ERROR) << "Could not parse the pinsets in the input JSON";
    return false;
  }

  for (size_t i = 0; i < pinsets_list->size(); ++i) {
    const base::Value::Dict* parsed = (*pinsets_list)[i].GetIfDict();
    if (!parsed) {
      LOG(ERROR) << "Could not parse pinset " << base::NumberToString(i)
                 << " in the input JSON";
      return false;
    }

    const std::string* maybe_name = parsed->FindString("name");
    if (!maybe_name) {
      LOG(ERROR) << "Could not extract the name for pinset "
                 << base::NumberToString(i) << " from the input JSON";
      return false;
    }
    std::string name = *maybe_name;

    const std::string* maybe_report_uri = parsed->FindString("report_uri");
    std::string report_uri =
        maybe_report_uri ? *maybe_report_uri : std::string();

    auto pinset = std::make_unique<Pinset>(name, report_uri);

    const base::Value::List* pinset_static_hashes_list =
        parsed->FindList("static_spki_hashes");
    if (pinset_static_hashes_list) {
      for (const auto& hash : *pinset_static_hashes_list) {
        if (!hash.is_string()) {
          LOG(ERROR) << "Could not parse static spki hash "
                     << hash.DebugString() << " in the input JSON";
          return false;
        }
        pinset->AddStaticSPKIHash(hash.GetString());
      }
    }

    const base::Value::List* pinset_bad_static_hashes_list =
        parsed->FindList("bad_static_spki_hashes");
    if (pinset_bad_static_hashes_list) {
      for (const auto& hash : *pinset_bad_static_hashes_list) {
        if (!hash.is_string()) {
          LOG(ERROR) << "Could not parse bad static spki hash "
                     << hash.DebugString() << " in the input JSON";
          return false;
        }
        pinset->AddBadStaticSPKIHash(hash.GetString());
      }
    }

    pinsets->RegisterPinset(std::move(pinset));
  }

  return true;
}

}  // namespace net::transport_security_state
```