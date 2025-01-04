Response:
Let's break down the thought process for analyzing the `root_store_tool.cc` file and answering the prompt's questions.

**1. Initial Scan and Purpose Identification:**

The first step is to quickly scan the file for keywords and structural elements. I see includes like `<iostream>`, `<string>`, `#include "base/..."`, `#include "net/..."`, and `#include "third_party/..."`. This immediately suggests a C++ program within a larger project (Chromium). The filename `root_store_tool.cc` and the inclusion of `"net/cert/root_store_proto_full/root_store.pb.h"` strongly hint at its purpose: managing root certificates for network security. The `main` function and command-line argument parsing confirm it's an executable tool.

**2. Deeper Dive into Functionality:**

Now, I'll read through the code more carefully, focusing on the key functions:

* **`DecodeCerts(std::string_view in)`:**  The name and the use of `PEM_read_bio` suggest it's responsible for parsing PEM-encoded certificates. The output is a map of SHA-256 hashes to the DER-encoded certificate content. This is crucial for identifying and managing certificates.

* **`ReadTextRootStore(const base::FilePath& root_store_path, const base::FilePath& certs_path)`:** This function reads a text-based protobuf file (`root_store_path`) representing the root store configuration. It also optionally reads a file containing PEM-encoded certificates (`certs_path`). It then combines these, matching certificate hashes in the protobuf to the actual certificate data. This is the core logic for loading the root store. The error handling (`LOG(ERROR)`) is also important to note.

* **`SecondsFromEpochToBaseTime`, `VersionFromString`:** These are helper functions for formatting data when generating C++ code.

* **`WriteRootCppFile(const RootStore& root_store, const base::FilePath cpp_path)`:** This function takes the loaded `RootStore` object and generates a C++ source file containing `constexpr` arrays and structs representing the root certificates and their constraints. This strongly indicates that the root store data is embedded directly into the Chromium binary. The code generation logic is detailed and includes handling for certificate data, constraints, and version information.

* **`WriteEvCppFile(const RootStore& root_store, const base::FilePath cpp_path)`:**  Similar to `WriteRootCppFile`, but specifically for EV (Extended Validation) certificates. It extracts relevant information like policy OIDs.

* **`main(int argc, char** argv)`:** The entry point of the tool. It handles command-line argument parsing using `base::CommandLine`, calls the reading and writing functions based on the provided arguments. The usage instructions printed to `std::cerr` are also significant.

**3. Answering the Prompt's Questions (with self-correction/refinement):**

* **Functionality:**  Based on the above analysis, I can list the core functionalities. I need to be precise and use technical terms where appropriate (e.g., "PEM", "DER", "protobuf").

* **Relationship to JavaScript:** I look for any direct interaction with JavaScript APIs or concepts. I find none. However, the *outcome* of this tool – the embedded root certificates – directly *impacts* how JavaScript running in a browser connects to websites securely. It's an indirect but crucial relationship. Initially, I might think there's no connection, but considering the browser's overall security architecture reveals the link.

* **Logical Reasoning (Hypothetical Input/Output):**  I need to choose a realistic scenario. Generating the C++ output is a key function. I can imagine providing a text protobuf file and a PEM certificate file as input and describe the generated C++ code containing the certificate data as output. I should also consider potential error scenarios (e.g., missing certificate).

* **User/Programming Errors:**  The error handling in the `ReadTextRootStore` and `DecodeCerts` functions provides clues about potential errors. Incorrect file paths, invalid PEM format, or inconsistencies between the protobuf and certificate files are likely culprits. I should also consider command-line usage errors.

* **User Operation and Debugging:**  This requires thinking about the *development workflow* where this tool would be used. It's likely part of the Chromium build process. The command-line arguments provide the entry points. Debugging would involve checking the input files, the command-line arguments, and the output of the tool, potentially using logging or a debugger. Tracing back how a specific root certificate gets into the browser involves understanding this generation process.

**4. Structuring the Answer:**

Finally, I organize the information into clear sections, addressing each part of the prompt systematically. Using bullet points, code snippets (where appropriate), and clear explanations makes the answer easier to understand. I also review the answer to ensure accuracy and completeness.

**Self-Correction Example during the process:**

Initially, I might focus too much on the low-level details of PEM parsing. However, the prompt asks for the *functionality* at a higher level. I need to summarize the PEM parsing as "decoding PEM-encoded certificates" rather than getting bogged down in the specifics of `BIO` and `PEM_read_bio`. Similarly, for the C++ code generation, I should focus on the *purpose* (embedding certificates) and the *types of data* included (certificate content, constraints) rather than reciting every line of generated code. The level of detail should match the question's intent.
This C++ source file, `root_store_tool.cc`, is a command-line utility within the Chromium project's network stack. Its primary function is to process and transform root certificate data into a format suitable for embedding directly into the Chromium browser.

Here's a breakdown of its functionalities:

**1. Reading and Parsing Root Store Configuration:**

* **Reads a text-based protobuf file (`.pb.txt`)**: This file (`--root-store`) contains the configuration of the root store, defining trust anchors (root certificates) and their associated constraints (e.g., SCT requirements, allowed DNS names, version restrictions).
* **Optionally reads PEM-encoded certificates (`.pem`)**: This file (`--certs`) contains the actual certificate data in PEM format.
* **Parses PEM certificates**: The `DecodeCerts` function extracts individual certificates from the PEM file and calculates their SHA-256 hash.
* **Matches certificate data to the protobuf**: The tool matches the SHA-256 hashes referenced in the root store protobuf with the actual certificate data read from the PEM file.
* **Handles certificate constraints**: It reads and processes constraints defined in the protobuf for each trust anchor.

**2. Generating C++ Source Files:**

* **Generates a C++ header file (`--write-cpp-root-store`)**: This file contains `constexpr` arrays of bytes representing the DER-encoded root certificates and their constraints. This allows the Chromium browser to directly include the root store data in its binary.
* **Generates a C++ header file for EV roots (`--write-cpp-ev-roots`)**: This file specifically targets Extended Validation (EV) certificates, extracting policy OIDs and generating a data structure (`EVMetadata`) used for EV certificate verification.

**3. (Potentially) Serializing the Root Store Proto:**

* **Writes a binary protobuf file (`--write-proto`)**:  While the comment suggests this is for future use (component update), the code includes functionality to serialize the parsed `RootStore` proto to a binary file.

**Relationship with JavaScript Functionality:**

This tool has an **indirect but crucial relationship** with JavaScript functionality in the browser.

* **Secure Connections (HTTPS):** JavaScript code running in a web page relies on the browser's ability to establish secure HTTPS connections. The root certificates generated by this tool are the foundation of that trust. When a website presents a certificate, the browser checks if its issuing Certificate Authority (CA) is present in the root store. If a valid chain of trust can be built back to a root certificate, the connection is deemed secure.
* **No Direct Interaction:**  The `root_store_tool.cc` itself does not directly interact with JavaScript code. It's a build-time tool. The output of this tool (the generated C++ header files) is compiled into the browser binary, which then affects the behavior of the browser's networking code, which in turn impacts the security context in which JavaScript runs.

**Example illustrating the relationship:**

1. **Input:** The `root_store_tool` is run with a `root_store.pb.txt` file containing information about the "Let's Encrypt Authority X3" root certificate and a `certs.pem` file containing the actual DER-encoded certificate.
2. **Processing:** The tool reads these files, parses the PEM certificate, calculates its hash, and matches it with the entry in the protobuf.
3. **Output:** The tool generates a `root_store.cc` file containing a `constexpr` array with the byte representation of the "Let's Encrypt Authority X3" certificate.
4. **Compilation:** This `root_store.cc` file is compiled into the Chromium browser.
5. **JavaScript Interaction:** When a JavaScript application running in the browser tries to connect to a website secured by a certificate issued by "Let's Encrypt Authority X3", the browser's networking code will consult the embedded root store (generated by this tool) and find the matching certificate, thus establishing a trusted HTTPS connection.

**Logical Reasoning (Hypothetical Input & Output):**

**Hypothetical Input:**

* **`root_store.pb.txt`:**
  ```protobuf
  version_major: 1
  trust_anchors {
    sha256_hex: "a8985d3a65e5e5c4b2d7d66d8ba6afb4cf0729049b461a0302c4a12b7ba8c7a7"
  }
  ```
* **`certs.pem`:**
  ```pem
  -----BEGIN CERTIFICATE-----
  MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
  ... (rest of the certificate data) ...
  -----END CERTIFICATE-----
  ```
  (Assuming the SHA-256 hash of the DER encoded content matches the one in `root_store.pb.txt`)

**Hypothetical Output (`root_store.cc`):**

```c++
// This file is auto-generated, DO NOT EDIT.

constexpr uint8_t kChromeRootCert0[] = {0x30, 0x82, 0x03, 0x9d, 0x30, 0x82, 0x02, 0x85, ...}; // DER encoded certificate data

constexpr ChromeRootCertInfo kChromeRootCertList[] = {
    {kChromeRootCert0, {}},
};

static const int64_t kRootStoreVersion = 1;
```

**Assumptions:**

* The `certs.pem` file contains a single certificate.
* The SHA-256 hash in the protobuf matches the actual certificate's hash.
* No constraints are defined for this trust anchor in the protobuf.

**User or Programming Common Usage Errors:**

1. **Incorrect File Paths:** Providing incorrect paths for `--root-store` or `--certs` will lead to file reading errors.
   ```bash
   ./root_store_tool --root-store=wrong_path.pb.txt --certs=certs.pem
   ```
   **Error Output:** `Could not read wrong_path.pb.txt`

2. **Mismatch between Proto and Certificate Data:** If the SHA-256 hash in the `root_store.pb.txt` doesn't match any certificate in `certs.pem`, the tool will fail.
   ```bash
   ./root_store_tool --root-store=root_store.pb.txt --certs=certs.pem
   ```
   **Error Output:** `Could not find certificate a8985d3a65e5e5c4b2d7d66d8ba6afb4cf0729049b461a0302c4a12b7ba8c7a7`

3. **Invalid PEM Format:** If the `certs.pem` file contains malformed PEM data, the `DecodeCerts` function will fail.
   ```bash
   ./root_store_tool --root-store=root_store.pb.txt --certs=malformed.pem
   ```
   **Error Output:** `Error reading PEM.`

4. **Missing Required Switches:** Running the tool without the `--root-store` switch will result in a usage error.
   ```bash
   ./root_store_tool --certs=certs.pem
   ```
   **Error Output:**  Prints the usage instructions to stderr.

5. **Unused Certificates:** If the `certs.pem` file contains certificates that are not referenced in the `root_store.pb.txt`, the tool will report an error.
   ```bash
   ./root_store_tool --root-store=root_store.pb.txt --certs=certs_with_extra.pem
   ```
   **Error Output:** `Unused certificate (SHA-256 hash ...) in certs_with_extra.pem`

**User Operation Steps to Reach This Code (Debugging Clues):**

The `root_store_tool` is typically used as part of the Chromium build process. A developer or build script would execute this tool to generate the necessary C++ source files before compiling the browser. Here's a possible sequence:

1. **Modifying Root Store Configuration:** A security engineer or developer might need to update the set of trusted root certificates. This could involve:
   * Adding a new root certificate to the trusted list.
   * Removing an outdated or compromised root certificate.
   * Modifying constraints for an existing root certificate (e.g., adjusting SCT requirements).
2. **Updating Input Files:** Based on the modifications, they would update the `root_store.pb.txt` file to reflect the changes in trust anchors and constraints. They might also need to add the new certificate (in PEM format) to the `certs.pem` file.
3. **Running the `root_store_tool`:** The build system or the developer would then execute the `root_store_tool` with the updated input files. The command might look something like this:
   ```bash
   ./out/Release/net/tools/root_store_tool/root_store_tool \
       --root-store=net/data/ssl/root_store.pb.txt \
       --certs=net/data/ssl/certificates.pem \
       --write-cpp-root-store=net/cert/root_store_generated.cc \
       --write-cpp-ev-roots=net/cert/ev_root_ca_metadata.cc
   ```
4. **Compilation:** The Chromium build system would then compile the generated `root_store_generated.cc` and `ev_root_ca_metadata.cc` files along with the rest of the browser's source code.

**Debugging Scenarios:**

* **A new website using a newly added root certificate isn't trusted:**
    * **Check `root_store.pb.txt`:** Ensure the new root certificate's SHA-256 hash is present.
    * **Check `certs.pem`:** Verify the certificate is present and in valid PEM format.
    * **Run `root_store_tool` manually:** Execute the tool with the relevant input files to see if it processes them correctly and generates the expected C++ output. Check for any error messages from the tool.
    * **Inspect generated C++:** Look at the generated `root_store_generated.cc` to confirm the new certificate's data is present.
* **Errors during the build process related to root certificates:**
    * **Examine the build logs:** Look for error messages specifically mentioning `root_store_tool` or related file paths.
    * **Verify input files:** Double-check the syntax and content of `root_store.pb.txt` and `certs.pem`.
    * **Check command-line arguments:** Ensure the `root_store_tool` is being called with the correct switches and file paths in the build scripts.

By understanding the purpose and functionality of `root_store_tool.cc`, developers can effectively debug issues related to root certificate management and the establishment of secure connections within the Chromium browser.

Prompt: 
```
这是目录为net/tools/root_store_tool/root_store_tool.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include <inttypes.h>

#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>

#include "base/at_exit.h"
#include "base/base_paths.h"
#include "base/command_line.h"
#include "base/containers/span.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/numerics/safe_conversions.h"
#include "base/path_service.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "crypto/sha2.h"
#include "net/cert/root_store_proto_full/root_store.pb.h"
#include "third_party/boringssl/src/include/openssl/bio.h"
#include "third_party/boringssl/src/include/openssl/err.h"
#include "third_party/boringssl/src/include/openssl/pem.h"
#include "third_party/protobuf/src/google/protobuf/text_format.h"

using chrome_root_store::RootStore;

namespace {

// Returns a map from hex-encoded SHA-256 hash to DER certificate, or
// `std::nullopt` if not found.
std::optional<std::map<std::string, std::string>> DecodeCerts(
    std::string_view in) {
  // TODO(crbug.com/40770548): net/cert/pem.h has a much nicer API, but
  // it would require some build refactoring to avoid a circular dependency.
  // This is assuming that the chrome trust store code goes in
  // net/cert/internal, which it may not.
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(in.data(), in.size()));
  if (!bio) {
    return std::nullopt;
  }
  std::map<std::string, std::string> certs;
  for (;;) {
    char* name;
    char* header;
    unsigned char* data;
    long len;
    if (!PEM_read_bio(bio.get(), &name, &header, &data, &len)) {
      uint32_t err = ERR_get_error();
      if (ERR_GET_LIB(err) == ERR_LIB_PEM &&
          ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
        // Found the last PEM block.
        break;
      }
      LOG(ERROR) << "Error reading PEM.";
      return std::nullopt;
    }
    bssl::UniquePtr<char> scoped_name(name);
    bssl::UniquePtr<char> scoped_header(header);
    bssl::UniquePtr<unsigned char> scoped_data(data);
    if (strcmp(name, "CERTIFICATE") != 0) {
      LOG(ERROR) << "Found PEM block of type " << name
                 << " instead of CERTIFICATE";
      return std::nullopt;
    }
    std::string sha256_hex =
        base::ToLowerASCII(base::HexEncode(crypto::SHA256Hash(
            base::make_span(data, base::checked_cast<size_t>(len)))));
    certs[sha256_hex] = std::string(data, data + len);
  }
  return std::move(certs);
}

std::optional<RootStore> ReadTextRootStore(
    const base::FilePath& root_store_path,
    const base::FilePath& certs_path) {
  std::string root_store_text;
  if (!base::ReadFileToString(base::MakeAbsoluteFilePath(root_store_path),
                              &root_store_text)) {
    LOG(ERROR) << "Could not read " << root_store_path;
    return std::nullopt;
  }

  RootStore root_store;
  if (!google::protobuf::TextFormat::ParseFromString(root_store_text,
                                                     &root_store)) {
    LOG(ERROR) << "Could not parse " << root_store_path;
    return std::nullopt;
  }

  std::map<std::string, std::string> certs;
  if (!certs_path.empty()) {
    std::string certs_data;
    if (!base::ReadFileToString(base::MakeAbsoluteFilePath(certs_path),
                                &certs_data)) {
      LOG(ERROR) << "Could not read " << certs_path;
      return std::nullopt;
    }
    auto certs_opt = DecodeCerts(certs_data);
    if (!certs_opt) {
      LOG(ERROR) << "Could not decode " << certs_path;
      return std::nullopt;
    }
    certs = std::move(*certs_opt);
  }

  // Replace the filenames with the actual certificate contents.
  for (auto& anchor : *root_store.mutable_trust_anchors()) {
    if (anchor.certificate_case() !=
        chrome_root_store::TrustAnchor::kSha256Hex) {
      continue;
    }

    auto iter = certs.find(anchor.sha256_hex());
    if (iter == certs.end()) {
      LOG(ERROR) << "Could not find certificate " << anchor.sha256_hex();
      return std::nullopt;
    }

    // Remove the certificate from `certs`. This both checks for duplicate
    // certificates and allows us to check for unused certificates later.
    anchor.set_der(std::move(iter->second));
    certs.erase(iter);
  }

  if (!certs.empty()) {
    LOG(ERROR) << "Unused certificate (SHA-256 hash " << certs.begin()->first
               << ") in " << certs_path;
    return std::nullopt;
  }

  return std::move(root_store);
}

std::string SecondsFromEpochToBaseTime(int64_t t) {
  return base::StrCat({"base::Time::UnixEpoch() + base::Seconds(",
                       base::NumberToString(t), ")"});
}

std::string VersionFromString(std::string_view version_str) {
  return base::StrCat({"\"", version_str, "\""});
}

// Returns true if file was correctly written, false otherwise.
bool WriteRootCppFile(const RootStore& root_store,
                      const base::FilePath cpp_path) {
  // Root store should have at least one trust anchors.
  CHECK_GT(root_store.trust_anchors_size(), 0);

  const std::string kNulloptString = "std::nullopt";

  std::string string_to_write =
      "// This file is auto-generated, DO NOT EDIT.\n\n";

  for (int i = 0; i < root_store.trust_anchors_size(); i++) {
    const auto& anchor = root_store.trust_anchors(i);
    // Every trust anchor at this point should have a DER.
    CHECK(!anchor.der().empty());
    std::string der = anchor.der();

    base::StringAppendF(&string_to_write,
                        "constexpr uint8_t kChromeRootCert%d[] = {", i);

    // Convert each character to hex representation, escaped.
    for (auto c : der) {
      base::StringAppendF(&string_to_write, "0x%02xu,",
                          static_cast<uint8_t>(c));
    }

    // End struct
    string_to_write += "};\n";

    if (anchor.constraints_size() > 0) {
      int constraint_num = 0;
      for (const auto& constraint : anchor.constraints()) {
        if (constraint.permitted_dns_names_size() > 0) {
          base::StringAppendF(&string_to_write,
                              "constexpr std::string_view "
                              "kChromeRootConstraint%dNames%d[] = {",
                              i, constraint_num);
          for (const auto& name : constraint.permitted_dns_names()) {
            base::StringAppendF(&string_to_write, "\"%s\",", name);
          }
          string_to_write += "};\n";
        }
        constraint_num++;
      }

      base::StringAppendF(&string_to_write,
                          "constexpr StaticChromeRootCertConstraints "
                          "kChromeRootConstraints%d[] = {",
                          i);

      std::vector<std::string> constraint_strings;
      constraint_num = 0;
      for (const auto& constraint : anchor.constraints()) {
        std::vector<std::string> constraint_params;

        constraint_params.push_back(
            constraint.has_sct_not_after_sec()
                ? SecondsFromEpochToBaseTime(constraint.sct_not_after_sec())
                : kNulloptString);

        constraint_params.push_back(
            constraint.has_sct_all_after_sec()
                ? SecondsFromEpochToBaseTime(constraint.sct_all_after_sec())
                : kNulloptString);

        constraint_params.push_back(
            constraint.has_min_version()
                ? VersionFromString(constraint.min_version())
                : kNulloptString);

        constraint_params.push_back(
            constraint.has_max_version_exclusive()
                ? VersionFromString(constraint.max_version_exclusive())
                : kNulloptString);

        if (constraint.permitted_dns_names_size() > 0) {
          constraint_params.push_back(base::StringPrintf(
              "kChromeRootConstraint%dNames%d", i, constraint_num));
        } else {
          constraint_params.push_back("{}");
        }

        constraint_strings.push_back(
            base::StrCat({"{", base::JoinString(constraint_params, ","), "}"}));

        constraint_num++;
      }

      string_to_write += base::JoinString(constraint_strings, ",");
      string_to_write += "};\n";
    }
  }

  string_to_write += "constexpr ChromeRootCertInfo kChromeRootCertList[] = {\n";

  for (int i = 0; i < root_store.trust_anchors_size(); i++) {
    const auto& anchor = root_store.trust_anchors(i);
    base::StringAppendF(&string_to_write, "    {kChromeRootCert%d, ", i);
    if (anchor.constraints_size() > 0) {
      base::StringAppendF(&string_to_write, "kChromeRootConstraints%d", i);
    } else {
      string_to_write += "{}";
    }
    string_to_write += "},\n";
  }
  string_to_write += "};";

  base::StringAppendF(&string_to_write,
                      "\n\n\nstatic const int64_t kRootStoreVersion = %" PRId64
                      ";\n",
                      root_store.version_major());
  if (!base::WriteFile(cpp_path, string_to_write)) {
    return false;
  }
  return true;
}

// Returns true if file was correctly written, false otherwise.
bool WriteEvCppFile(const RootStore& root_store,
                    const base::FilePath cpp_path) {
  // There should be at least one EV root.
  CHECK_GT(root_store.trust_anchors_size(), 0);

  std::string string_to_write =
      "// This file is auto-generated, DO NOT EDIT.\n\n"
      "static const EVMetadata kEvRootCaMetadata[] = {\n";

  for (auto& anchor : root_store.trust_anchors()) {
    // Every trust anchor at this point should have a DER.
    CHECK(!anchor.der().empty());
    if (anchor.ev_policy_oids_size() == 0) {
      // The same input file is used for the Chrome Root Store and EV enabled
      // certificates. Skip anchors that have no EV policy OIDs when generating
      // the EV include file.
      continue;
    }

    std::string sha256_hash = crypto::SHA256HashString(anchor.der());

    // Begin struct. Assumed type of EVMetadata:
    //
    // struct EVMetadata {
    //  static const size_t kMaxOIDsPerCA = 2;
    //  SHA256HashValue fingerprint;
    //  const std::string_view policy_oids[kMaxOIDsPerCA];
    // };
    string_to_write += "    {\n";
    string_to_write += "        {{";

    int wrap_count = 0;
    for (auto c : sha256_hash) {
      if (wrap_count != 0) {
        if (wrap_count % 11 == 0) {
          string_to_write += ",\n          ";
        } else {
          string_to_write += ", ";
        }
      }
      base::StringAppendF(&string_to_write, "0x%02x", static_cast<uint8_t>(c));
      wrap_count++;
    }

    string_to_write += "}},\n";
    string_to_write += "        {\n";

    // struct expects exactly two policy oids, and we can only support 1 or 2
    // policy OIDs. These checks will need to change if we ever merge the EV and
    // Chrome Root Store textprotos.
    const int kMaxPolicyOids = 2;
    int oids_size = anchor.ev_policy_oids_size();
    std::string hexencode_hash = base::HexEncode(sha256_hash);
    if (oids_size > kMaxPolicyOids) {
      PLOG(ERROR) << hexencode_hash << " has too many OIDs!";
      return false;
    }
    for (int i = 0; i < kMaxPolicyOids; i++) {
      std::string oid;
      if (i < oids_size) {
        oid = anchor.ev_policy_oids(i);
      }
      string_to_write += "            \"" + oid + "\",\n";
    }

    // End struct
    string_to_write += "        },\n";
    string_to_write += "    },\n";
  }
  string_to_write += "};\n";
  if (!base::WriteFile(cpp_path, string_to_write)) {
    PLOG(ERROR) << "Error writing cpp include file";
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit_manager;
  base::CommandLine::Init(argc, argv);

  logging::LoggingSettings settings;
  settings.logging_dest =
      logging::LOG_TO_SYSTEM_DEBUG_LOG | logging::LOG_TO_STDERR;
  logging::InitLogging(settings);

  base::CommandLine& command_line = *base::CommandLine::ForCurrentProcess();
  base::FilePath proto_path = command_line.GetSwitchValuePath("write-proto");
  base::FilePath root_store_cpp_path =
      command_line.GetSwitchValuePath("write-cpp-root-store");
  base::FilePath ev_roots_cpp_path =
      command_line.GetSwitchValuePath("write-cpp-ev-roots");
  base::FilePath root_store_path =
      command_line.GetSwitchValuePath("root-store");
  base::FilePath certs_path = command_line.GetSwitchValuePath("certs");

  if ((proto_path.empty() && root_store_cpp_path.empty() &&
       ev_roots_cpp_path.empty()) ||
      root_store_path.empty() || command_line.HasSwitch("help")) {
    std::cerr << "Usage: root_store_tool "
              << "--root-store=TEXTPROTO_FILE "
              << "[--certs=CERTS_FILE] "
              << "[--write-proto=PROTO_FILE] "
              << "[--write-cpp-root-store=CPP_FILE] "
              << "[--write-cpp-ev-roots=CPP_FILE] " << std::endl;
    return 1;
  }

  std::optional<RootStore> root_store =
      ReadTextRootStore(root_store_path, certs_path);
  if (!root_store) {
    return 1;
  }

  // TODO(crbug.com/40770548): Figure out how to use the serialized
  // proto to support component update.
  // components/resources/ssl/ssl_error_assistant/push_proto.py
  // does it through a GCS bucket (I think) so that might be an option.
  if (!proto_path.empty()) {
    std::string serialized;
    if (!root_store->SerializeToString(&serialized)) {
      LOG(ERROR) << "Error serializing root store proto"
                 << root_store->DebugString();
      return 1;
    }
    if (!base::WriteFile(proto_path, serialized)) {
      PLOG(ERROR) << "Error writing serialized proto root store";
      return 1;
    }
  }

  if (!root_store_cpp_path.empty() &&
      !WriteRootCppFile(*root_store, root_store_cpp_path)) {
    PLOG(ERROR) << "Error writing root store C++ include file";
    return 1;
  }
  if (!ev_roots_cpp_path.empty() &&
      !WriteEvCppFile(*root_store, ev_roots_cpp_path)) {
    PLOG(ERROR) << "Error writing EV roots C++ include file";
    return 1;
  }

  return 0;
}

"""

```