Response:
Let's break down the thought process for analyzing this Python code and generating the detailed explanation.

**1. Understanding the Goal:**

The request asks for a comprehensive breakdown of the `machine_spec.py` file within the Frida project. The focus is on its functionalities, connections to reverse engineering, low-level details (binary, kernel, etc.), logical reasoning, potential user errors, and how a user might end up interacting with this code.

**2. Initial Code Scan and High-Level Purpose:**

First, I read through the code to get a general understanding. I immediately recognize the `@dataclass` decorator, indicating this class is primarily for holding data. The methods within the class suggest it's about identifying and manipulating information related to a machine's operating system and architecture. The names of the methods like `make_from_local_system`, `parse`, `evolve`, and properties like `identifier`, `os_dash_arch` strongly suggest this.

**3. Deeper Dive into Functionality:**

Next, I examine each method and property in detail:

* **`MachineSpec` constructor:**  Stores OS, architecture, config, and triplet.
* **`make_from_local_system`:**  Uses `platform` module to detect the current system's OS and architecture.
* **`parse`:** This is crucial. It takes a string and attempts to extract OS, architecture, config, and triplet. The logic involving splitting by hyphens and regular expressions (`TARGET_TRIPLET_ARCH_PATTERN`) stands out. This is where much of the intelligence lies in understanding machine specifications.
* **`evolve`:** Creates a new `MachineSpec` based on the current one, allowing selective modification of attributes.
* **`default_missing`:**  Handles default configurations, particularly for Windows with MSVC.
* **`maybe_adapt_to_host`:** Attempts to reconcile the target machine spec with the host machine spec, useful in cross-compilation or remote debugging scenarios.
* **Properties:**  Each property provides a derived piece of information about the machine specification (identifier, OS-arch, endianness, etc.). I note the logic within each property to understand how it's calculated.
* **`__eq__`:**  Defines how to check if two `MachineSpec` objects are equal.
* **`detect_os` and `detect_arch`:** Simple helper functions using the `platform` module.
* **Constants (`ARCHS`, `KERNELS`, etc.):** These dictionaries and sets provide mappings and definitions for various OSes, architectures, and configurations.

**4. Connecting to Reverse Engineering:**

With the understanding of the core functionality, I start thinking about how this relates to reverse engineering:

* **Target Identification:** Frida is used for dynamic analysis, often on remote devices or processes. Knowing the target's OS and architecture is essential for selecting the correct Frida gadget (agent). This class directly facilitates that.
* **Cross-Compilation/Remote Debugging:**  The `maybe_adapt_to_host` method hints at scenarios where Frida is built on one machine but targets another.
* **Understanding Binary Structure:**  Properties like `endian` and `pointer_size` are directly relevant to how data is laid out in memory and within binaries.

**5. Low-Level Details (Binary, Kernel, Android):**

I look for specific parts of the code that touch on low-level concepts:

* **Operating Systems:** The code explicitly handles Windows, macOS, Linux, Android, iOS, etc. The `KERNELS` dictionary links OS names to their underlying kernel names.
* **Architectures:** It deals with x86, ARM, ARM64, MIPS, etc.
* **Configurations:** The concept of "config" (like `mingw` or `mt`) relates to compiler settings and linking, which affects the final binary.
* **Android:** The `CPU_TYPES_PER_OS_OVERRIDES` dictionary has a specific section for "android," indicating awareness of Android-specific CPU naming conventions.

**6. Logical Reasoning and Examples:**

I identify areas where the code makes decisions based on input:

* **`parse`:** The logic of splitting the input string and the regular expression matching are key examples. I consider different input strings and trace how they would be parsed. This helps in understanding the assumptions and limitations of the parsing logic. *Hypothetical Input/Output examples are generated.*
* **`default_missing`:** The logic of setting the `config` based on `toolchain_is_msvc` and `recommended_vscrt` is another example.

**7. User Errors:**

I consider how a user might misuse the code or provide incorrect input:

* **Incorrect `raw_spec`:**  Providing a string that doesn't conform to the expected format in `parse` is a prime example.
* **Misunderstanding identifiers:**  Users might provide the wrong identifier string when trying to specify a target.

**8. Tracing User Interaction (Debugging Clues):**

I think about how a user would interact with Frida and how this specific code file might be involved:

* **Frida CLI:**  Commands like `frida -H <target>` likely involve parsing the target specification.
* **Frida scripts:**  A script might need to determine the architecture of the target process.
* **Frida build process:** This file is likely used during the building of Frida itself to determine the target platform.

**9. Structuring the Explanation:**

Finally, I organize the findings into the requested categories:

* **Functionality:** A clear list of what the code does.
* **Relationship to Reverse Engineering:**  Concrete examples.
* **Binary/Kernel/Android:** Specific code snippets or logic that relate to these.
* **Logical Reasoning:**  Hypothetical input/output scenarios.
* **User Errors:**  Practical examples of misuse.
* **User Operation (Debugging):**  Tracing how a user might indirectly interact with this code.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the `parse` function is overly complex. *Correction:* Realized it handles various target specification formats, making it necessary.
* **Initial thought:** Focus heavily on individual methods. *Correction:*  Shifted to show how the methods work together to achieve the overall goal of machine specification handling.
* **Ensuring clarity:**  Used clear and concise language, providing examples where needed. Made sure to connect the technical details back to the broader context of Frida and reverse engineering.

By following this systematic approach, breaking down the code, and thinking about its context and potential use cases, I could generate a comprehensive and informative explanation.
This Python code defines a `MachineSpec` class within the Frida dynamic instrumentation tool. Its primary function is to **represent and parse specifications of target machines (operating system and architecture)** where Frida agents might run. This is crucial for Frida to build and deploy the correct components for a given target environment.

Let's break down its functionalities and connections:

**1. Core Functionality: Representing Machine Specifications**

* **Data Storage:** The `MachineSpec` class uses a `dataclass` to hold key information about a machine:
    * `os` (operating system): e.g., "windows", "linux", "android", "ios".
    * `arch` (architecture): e.g., "x86_64", "arm64", "armhf".
    * `config` (optional configuration): e.g., "mingw", "musl". This often relates to the C runtime library used.
    * `triplet` (optional full target triplet): A more complete identifier, like "aarch64-linux-gnu".

* **Creating Machine Specifications:**
    * `make_from_local_system()`:  Detects the operating system and architecture of the machine where the script is currently running using the `platform` module. This is useful for determining the host system's specifications.
    * `parse(raw_spec: str)`: This is a key function. It takes a string representing a machine specification and attempts to parse it into a `MachineSpec` object. It handles various formats of target triplets and simpler "os-arch" combinations. This is essential for users to specify their target environment.
    * `evolve(...)`: Creates a new `MachineSpec` by copying the current one and optionally overriding specific attributes. This allows for easy modification of existing specifications.
    * `default_missing(...)`:  Provides default values for missing configuration options, especially related to the Visual C++ runtime on Windows.
    * `maybe_adapt_to_host(...)`:  Attempts to adapt the current `MachineSpec` to match the provided `host_machine` specification. This is likely used in scenarios where Frida is built on one machine but targets another.

* **Accessing Machine Information (Properties):** The class provides various properties to access and derive information about the machine specification:
    * `identifier`: A canonical string representation of the OS, architecture, and config.
    * `os_dash_arch`, `os_dash_config`:  Convenient ways to get specific parts of the identifier.
    * `config_is_optimized`:  Indicates if the configuration suggests an optimized build.
    * `meson_optimization_options`: Returns Meson build system options for optimization based on the config.
    * `executable_suffix`: Returns the appropriate executable extension (.exe on Windows).
    * `msvc_platform`: Returns the platform string used by Microsoft Visual C++.
    * `is_apple`:  Checks if the OS is one of Apple's operating systems.
    * `system`, `subsystem`, `kernel`, `cpu_family`, `cpu`: Provide more granular information about the system. These often involve lookups in dictionaries (`KERNELS`, `CPU_FAMILIES`, `CPU_TYPES`, etc.).
    * `endian`:  Indicates the byte order (big or little endian) of the target architecture.
    * `pointer_size`:  Returns the size of a pointer in bytes on the target architecture.
    * `libdatadir`:  Specifies the directory for library data.
    * `toolchain_is_msvc`, `toolchain_can_strip`:  Indicate characteristics of the toolchain used for building.

* **Equality Check (`__eq__`)**: Defines how to compare two `MachineSpec` objects for equality based on their identifier.

* **Helper Functions (`detect_os`, `detect_arch`):**  Use the `platform` module to get the OS and architecture of the current system.

* **Constants:**  The file defines various dictionaries and sets (`ARCHS`, `KERNELS`, `CPU_FAMILIES`, `CPU_TYPES`, `BIG_ENDIAN_ARCHS`) to map common system and architecture names to more standardized or internal representations. The `TARGET_TRIPLET_ARCH_PATTERN` uses a regular expression to validate the architecture part of a target triplet.

**2. Relationship to Reverse Engineering**

This file is fundamentally related to reverse engineering because Frida is a powerful tool used for dynamic analysis and reverse engineering of software. Understanding the target environment is **absolutely critical** for Frida to function correctly.

* **Target Identification:** When a user wants to use Frida to inspect a process or a device, they need to specify the target. This file provides the mechanisms to represent and parse that target specification (e.g., through the `parse` method). For example, a user might specify a remote Android device using its architecture.

* **Selecting the Correct Frida Gadget:** Frida works by injecting an agent (a shared library) into the target process. The correct agent needs to be built for the specific OS and architecture of the target. The `MachineSpec` helps Frida determine which pre-built gadget or which compilation steps are necessary.

* **Cross-Platform Analysis:**  Frida can run on one platform (the host) and analyze processes running on a different platform (the target). The `maybe_adapt_to_host` function suggests this capability, allowing Frida to reconcile the target specification with the host's capabilities.

* **Understanding Target Binary Structure:** Properties like `endian` and `pointer_size` are directly relevant to understanding the memory layout and data representation within the target process's binary. Reverse engineers need to know if the target is big-endian or little-endian and the pointer size to correctly interpret memory dumps and function arguments.

**Example:**

Imagine you are reverse engineering an Android application on an ARM64 device. You might use the Frida command-line tool and specify the target like this:

```bash
frida -U -f com.example.myapp
```

Internally, Frida will use information about the connected Android device. This `machine_spec.py` file would be involved in:

1. **Detection:** Frida might internally use `make_from_local_system()` to know its own OS and architecture.
2. **Target Device Information:**  When connecting to the Android device, Frida will likely retrieve information about its OS (Android) and architecture (arm64). This information could be used to create a `MachineSpec` object, potentially using the `parse` method if the information comes as a string.
3. **Gadget Selection:** Based on the `MachineSpec` of the Android device, Frida will choose the appropriate pre-built Frida gadget for ARM64 Android.
4. **Communication:**  Knowing the `endian` and `pointer_size` of the target device is crucial for Frida to correctly communicate with the injected agent and interpret data from the target process.

**3. Involvement of Binary底层, Linux, Android 内核及框架的知识**

The code directly interacts with these low-level concepts:

* **Binary 底层 (Binary Undercarriage):**
    * **Architecture (arch):** The code explicitly handles different CPU architectures like x86, ARM, ARM64, MIPS. These architectures have different instruction sets, register sizes, and memory models, all crucial for binary analysis.
    * **Endianness (endian):** The `endian` property directly addresses the byte order of the target system, which is a fundamental aspect of binary data interpretation.
    * **Pointer Size (pointer_size):**  The `pointer_size` property is essential for understanding memory addressing and data structures within the target binary.
    * **Executable Suffix:** Knowing the correct executable suffix (`.exe` on Windows) is necessary for interacting with the file system.

* **Linux Kernel:**
    * **Operating System Detection:** The `detect_os()` function uses `platform.system()`, which relies on the underlying operating system's identification mechanisms.
    * **Kernel Names:** The `KERNELS` dictionary maps OS names to their kernel names (e.g., "linux" to "linux"). This can be relevant for understanding system calls and kernel-level interactions.
    * **Target Triplets:** The parsing logic in `parse()` often deals with Linux-style target triplets (e.g., "aarch64-linux-gnu").

* **Android Kernel and Framework:**
    * **Android as an OS:** The code explicitly treats "android" as a distinct operating system.
    * **CPU Type Overrides:** The `CPU_TYPES_PER_OS_OVERRIDES` dictionary has a specific entry for "android," indicating awareness of Android-specific CPU naming conventions (e.g., mapping "x86" to "i686").
    * **Toolchain Considerations:** The handling of `config` (e.g., `musl`) can be relevant for Android NDK builds.

**4. Logic Reasoning: Assumptions and Examples**

The `parse` method demonstrates logical reasoning based on the format of the input string:

**Assumptions in `parse`:**

* **Hyphen Separation:** It assumes that the components of a detailed specification (architecture, kernel, system) are separated by hyphens.
* **Order of Tokens:**  It expects a specific order of tokens (architecture, kernel, system) in longer specifications.
* **Keyword Recognition:** It recognizes keywords like "w64" for Windows, "nto" for QNX, and prefixes like "musl" for libc.
* **Architecture Pattern:** It uses a regular expression (`TARGET_TRIPLET_ARCH_PATTERN`) to validate the architecture part of a triplet.

**Example of Input and Output for `parse`:**

* **Input:** `"x86_64-linux-gnu"`
    * **Logic:** Splits by "-", resulting in `["x86_64", "linux", "gnu"]`. Matches the pattern for a target triplet.
    * **Output:** `MachineSpec(os='linux', arch='x86_64', config=None, triplet='x86_64-linux-gnu')`

* **Input:** `"arm-gnueabihf"`
    * **Logic:** Splits by "-", resulting in `["arm", "gnueabihf"]`. Matches the pattern for a target triplet. Recognizes "gnueabihf" and adjusts `arch` to "armhf".
    * **Output:** `MachineSpec(os='linux', arch='armhf', config=None, triplet='arm-gnueabihf')`

* **Input:** `"windows-x86"`
    * **Logic:** Splits by "-", resulting in `["windows", "x86"]`. Doesn't match the full triplet pattern, so it's treated as os and arch directly.
    * **Output:** `MachineSpec(os='windows', arch='x86', config=None, triplet=None)`

* **Input:** `"aarch64-nto-qnx7"`
    * **Logic:** Splits by "-", resulting in `["aarch64", "nto", "qnx7"]`. Matches the triplet pattern. Recognizes "nto" for QNX.
    * **Output:** `MachineSpec(os='qnx', arch='arm64', config=None, triplet='aarch64-nto-qnx7')`

**5. User and Programming Common Usage Errors**

* **Incorrect `raw_spec` Format:**
    * **Error:** Providing a string to `parse` that doesn't conform to the expected formats (e.g., missing hyphens, incorrect ordering of components, typos in OS or architecture names).
    * **Example:**  `MachineSpec.parse("x86linuxgnu")`  (missing hyphens) or `MachineSpec.parse("gnu-linux-x86_64")` (incorrect order).
    * **Consequences:** The parsing logic might fail to extract the correct information, leading to incorrect assumptions about the target environment and potentially causing Frida to fail to connect or function correctly.

* **Providing Ambiguous or Incomplete Specifications:**
    * **Error:** Providing only the OS without the architecture, or vice-versa, when more specific information is needed.
    * **Example:**  Trying to target a Linux system but not specifying whether it's x86, ARM, or ARM64.
    * **Consequences:** Frida might not be able to select the correct components or might make incorrect assumptions about the target.

* **Assuming Default Configurations:**
    * **Error:**  Not understanding or neglecting the `config` parameter, especially on Windows where the choice between `mingw` and MSVC (with its runtime linking options) is crucial.
    * **Example:**  Building a Frida module expecting MSVC runtime libraries to be present when targeting a MinGW environment, or vice-versa.
    * **Consequences:**  Compatibility issues and runtime errors when the Frida agent is injected into the target process.

* **Case Sensitivity:** While the code generally converts inputs to lowercase, users might make errors with capitalization when providing specifications.

**6. User Operation Steps to Reach This Code (Debugging Clues)**

A user's interaction might lead to this code being executed in several ways:

1. **Using the Frida Command-Line Interface (CLI):**
   * **Step 1:** User types a Frida command that targets a specific process or device.
   * **Step 2:** The Frida CLI needs to determine the OS and architecture of the target.
   * **Step 3:** The CLI might call `MachineSpec.parse()` to interpret the target specification provided by the user (e.g., through `-H` or `-U` flags).
   * **Step 4:**  The `MachineSpec` object is then used internally to select the correct Frida gadget, establish a connection, etc.

2. **Developing Frida Gadgets or Tools:**
   * **Step 1:** A developer is writing a Frida gadget or a Python script that uses the Frida API.
   * **Step 2:** The developer might need to determine the architecture of the target process programmatically.
   * **Step 3:**  The developer might use `frida.get_device()` or similar API calls, which internally might utilize `MachineSpec.make_from_local_system()` or retrieve target information and parse it using `MachineSpec.parse()`.
   * **Step 4:** The `MachineSpec` object helps the script make decisions based on the target environment.

3. **Building Frida from Source:**
   * **Step 1:** A user is building Frida from its source code.
   * **Step 2:** The build system (likely using Meson) needs to determine the target platform for which to compile Frida.
   * **Step 3:** The build scripts might use `MachineSpec.make_from_local_system()` to identify the host system or allow the user to specify a target platform, which would be parsed using `MachineSpec.parse()`.
   * **Step 4:** The `MachineSpec` object guides the build process, influencing compiler flags, library linking, and the selection of target-specific code.

4. **Debugging Frida Itself:**
   * **Step 1:** A developer is debugging issues within the Frida codebase.
   * **Step 2:** The developer might set breakpoints or trace execution within `machine_spec.py` to understand how target specifications are being parsed and handled.
   * **Step 3:** By examining the input to `MachineSpec.parse()` and the resulting `MachineSpec` object, they can diagnose problems related to target identification.

In essence, any interaction with Frida that involves targeting a specific system or process will likely involve the `MachineSpec` class to represent and reason about the characteristics of that target environment. This makes it a fundamental component for the proper functioning of the Frida dynamic instrumentation tool.

### 提示词
```
这是目录为frida/releng/machine_spec.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
from __future__ import annotations
from dataclasses import dataclass
import platform
import re
from typing import Optional


@dataclass
class MachineSpec:
    os: str
    arch: str
    config: Optional[str] = None
    triplet: Optional[str] = None

    @staticmethod
    def make_from_local_system() -> MachineSpec:
        return MachineSpec(detect_os(), detect_arch())

    @staticmethod
    def parse(raw_spec: str) -> MachineSpec:
        os = None
        arch = None
        config = None
        triplet = None

        tokens = raw_spec.split("-")
        if len(tokens) in {3, 4}:
            arch = tokens[0]
            m = TARGET_TRIPLET_ARCH_PATTERN.match(arch)
            if m is not None:
                kernel = tokens[-2]
                system = tokens[-1]

                if kernel == "w64":
                    os = "windows"
                elif kernel == "nto":
                    os = "qnx"
                else:
                    os = kernel

                if arch[0] == "i":
                    arch = "x86"
                elif arch == "arm":
                    if system == "gnueabihf":
                        arch = "armhf"
                    elif os == "qnx" and system.endswith("eabi"):
                        arch = "armeabi"
                elif arch == "aarch64":
                    arch = "arm64"

                if system.startswith("musl"):
                    config = "musl"
                elif kernel == "w64":
                    config = "mingw"

                triplet = raw_spec

        if os is None:
            os, arch, *rest = tokens
            if rest:
                assert len(rest) == 1
                config = rest[0]

        return MachineSpec(os, arch, config, triplet)

    def evolve(self,
               os: Optional[str] = None,
               arch: Optional[str] = None,
               config: Optional[str] = None,
               triplet: Optional[str] = None) -> MachineSpec:
        return MachineSpec(
            os if os is not None else self.os,
            arch if arch is not None else self.arch,
            config if config is not None else self.config,
            triplet if triplet is not None else self.triplet,
        )

    def default_missing(self, recommended_vscrt: Optional[str] = None) -> MachineSpec:
        config = self.config
        if config is None and self.toolchain_is_msvc:
            if recommended_vscrt is not None:
                config = recommended_vscrt
            else:
                config = "mt"
        return self.evolve(config=config)

    def maybe_adapt_to_host(self, host_machine: MachineSpec) -> MachineSpec:
        if self.identifier == host_machine.identifier and host_machine.triplet is not None:
            return host_machine
        if self.os == "windows":
            if host_machine.arch in {"x86_64", "x86"}:
                return host_machine
            if self.arch == host_machine.arch:
                return host_machine
        return self

    @property
    def identifier(self) -> str:
        parts = [self.os, self.arch]
        if self.config is not None:
            parts += [self.config]
        return "-".join(parts)

    @property
    def os_dash_arch(self) -> str:
        return f"{self.os}-{self.arch}"

    @property
    def os_dash_config(self) -> str:
        parts = [self.os]
        if self.config is not None:
            parts += [self.config]
        return "-".join(parts)

    @property
    def config_is_optimized(self) -> bool:
        if self.toolchain_is_msvc:
            return self.config in {"md", "mt"}
        return True

    @property
    def meson_optimization_options(self) -> list[str]:
        if self.config_is_optimized:
            optimization = "s"
            ndebug = "true"
        else:
            optimization = "0"
            ndebug = "false"
        return [
            f"-Doptimization={optimization}",
            f"-Db_ndebug={ndebug}",
        ]

    @property
    def executable_suffix(self) -> str:
        return ".exe" if self.os == "windows" else ""

    @property
    def msvc_platform(self) -> str:
        return "x64" if self.arch == "x86_64" else self.arch

    @property
    def is_apple(self) -> str:
        return self.os in {"macos", "ios", "watchos", "tvos"}

    @property
    def system(self) -> str:
        return "darwin" if self.is_apple else self.os

    @property
    def subsystem(self) -> str:
        return self.os_dash_config if self.is_apple else self.os

    @property
    def kernel(self) -> str:
        return KERNELS.get(self.os, self.os)

    @property
    def cpu_family(self) -> str:
        arch = self.arch
        return CPU_FAMILIES.get(arch, arch)

    @property
    def cpu(self) -> str:
        arch = self.arch

        mappings_to_search = [
            CPU_TYPES_PER_OS_OVERRIDES.get(self.os, {}),
            CPU_TYPES,
        ]
        for m in mappings_to_search:
            cpu = m.get(arch, None)
            if cpu is not None:
                return cpu

        return arch

    @property
    def endian(self) -> str:
        return "big" if self.arch in BIG_ENDIAN_ARCHS else "little"

    @property
    def pointer_size(self) -> int:
        arch = self.arch
        if arch in {"x86_64", "s390x"}:
            return 8
        if arch.startswith("arm64") or arch.startswith("mips64"):
            return 8
        return 4

    @property
    def libdatadir(self) -> str:
        return "libdata" if self.os == "freebsd" else "lib"

    @property
    def toolchain_is_msvc(self) -> bool:
        return self.os == "windows" and self.config != "mingw"

    @property
    def toolchain_can_strip(self) -> bool:
        return not self.toolchain_is_msvc

    def __eq__(self, other):
        if isinstance(other, MachineSpec):
            return other.identifier == self.identifier
        return False


def detect_os() -> str:
    os = platform.system().lower()
    if os == "darwin":
        os = "macos"
    return os


def detect_arch() -> str:
    arch = platform.machine().lower()
    return ARCHS.get(arch, arch)


ARCHS = {
    "amd64": "x86_64",
    "armv7l": "armhf",
    "aarch64": "arm64",
}

KERNELS = {
    "windows": "nt",

    "macos":   "xnu",
    "ios":     "xnu",
    "watchos": "xnu",
    "tvos":    "xnu",

    "qnx":     "nto",
}

CPU_FAMILIES = {
    "armbe8":     "arm",
    "armeabi":    "arm",
    "armhf":      "arm",

    "arm64":      "aarch64",
    "arm64e":     "aarch64",
    "arm64eoabi": "aarch64",

    "mipsel":     "mips",
    "mips64el":   "mips64",

    "powerpc":    "ppc"
}

CPU_TYPES = {
    "arm":        "armv7",
    "armbe8":     "armv6",
    "armhf":      "armv7hf",
    "armeabi":    "armv7eabi",

    "arm64":      "aarch64",
    "arm64e":     "aarch64",
    "arm64eoabi": "aarch64",
}

CPU_TYPES_PER_OS_OVERRIDES = {
    "linux": {
        "arm":        "armv5t",
        "armbe8":     "armv6t",
        "armhf":      "armv7a",

        "mips":       "mips1",
        "mipsel":     "mips1",

        "mips64":     "mips64r2",
        "mips64el":   "mips64r2",
    },
    "android": {
        "x86":        "i686",
    },
    "qnx": {
        "arm":        "armv6",
        "armeabi":    "armv7",
    },
}

BIG_ENDIAN_ARCHS = {
    "armbe8",
    "mips",
    "mips64",
    "ppc",
    "ppc64",
    "s390x",
}

TARGET_TRIPLET_ARCH_PATTERN = re.compile(r"^(i.86|x86_64|arm(v\w+)?|aarch64|mips\w*|powerpc|s390x)$")
```