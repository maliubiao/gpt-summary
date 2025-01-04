Response:
Let's break down the thought process to analyze this Python code and answer the user's request.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of a specific Python file within the Frida project. This involves identifying what the code *does*, how it interacts with the system, and potential implications for reverse engineering.

**2. Initial Scan and Identification of Key Areas:**

The first step is to quickly read through the code, identifying the major components and keywords. This involves looking for:

* **Imports:**  Libraries used (e.g., `os`, `re`, `subprocess`). This gives hints about the types of operations performed.
* **Class Definitions:**  `GLDependencySystem`, `GnuStepDependency`, `SDL2DependencyConfigTool`, `WxDependency`, `VulkanDependencySystem`. These are the core building blocks and likely represent the main functionalities.
* **Function Definitions within Classes:**  `__init__`, `find_config`, `weird_filter`, `filter_args`, `detect_version`, `get_requested`. These detail the specific actions each class can perform.
* **String Literals and Comments:** Look for informative strings, especially in `__init__` methods or comments explaining the purpose of certain code blocks. The SPDX license and copyright information are noted but less relevant to the functional analysis.
* **Keywords Related to Dependencies:**  Terms like "dependency," "link_args," "compile_args," "header," "library," "config." These strongly suggest the file is about managing external libraries.
* **Platform-Specific Checks:**  `is_darwin()`, `is_windows()`. This indicates the code adapts to different operating systems.
* **External Tool Invocations:**  Calls to tools like `gnustep-config`, `sdl2-config`, `wx-config`. This signifies interaction with system utilities.
* **Error Handling/Exceptions:** `DependencyException`, `FileNotFoundError`, `PermissionError`. This points to how the code handles failures.

**3. Focusing on Core Functionality - Dependency Detection:**

The overall structure clearly points to *dependency management*. Each class seems responsible for detecting and providing information about a specific UI-related library (OpenGL, GnuStep, SDL2, WxWidgets, Vulkan).

**4. Analyzing Each Class Individually:**

* **`GLDependencySystem`:**  Simple. Detects OpenGL based on the OS. On macOS and Windows, it hardcodes the link arguments. On other systems, it tries to find the library and header using compiler methods.
* **`GnuStepDependency`:** More complex. Uses `gnustep-config` to get compiler and linker flags. It handles different "modules" and has specific filtering logic (`weird_filter`, `filter_args`). The `detect_version` method is interesting, involving invoking `gmake`.
* **`SDL2DependencyConfigTool`:** Straightforward. Uses `sdl2-config` to fetch compile and link flags.
* **`WxDependency`:** Also uses a config tool (`wx-config`). It handles static linking and module requests. The error handling around static libraries is notable.
* **`VulkanDependencySystem`:** Detects Vulkan either by checking the `VULKAN_SDK` environment variable or by searching standard library paths. It attempts to determine the Vulkan version by compiling and running a simple program.

**5. Connecting to Reverse Engineering:**

Now, the key is to connect these functionalities to reverse engineering.

* **Dependency Identification:** Reverse engineers often need to understand what libraries an application uses. This code automates that process for the build system.
* **Compiler/Linker Flags:** Knowing the compile and link flags used to build an application can be crucial for recreating the build environment or understanding how the application interacts with its dependencies.
* **Platform-Specific Differences:**  The code highlights how dependencies are handled differently across operating systems, which is a significant factor in reverse engineering multi-platform applications.
* **Dynamic Instrumentation (Frida Context):**  The fact that this file is in the Frida project is a strong clue. Frida is used for dynamic instrumentation, which involves injecting code into running processes. Understanding the dependencies of the target process is a prerequisite for successful instrumentation.

**6. Identifying Binary/Kernel/Framework Relevance:**

* **OpenGL/Vulkan:** These are graphics APIs directly interacting with the GPU and underlying graphics drivers/kernel modules.
* **Operating System Libraries:**  The code interacts with system libraries (e.g., finding `GL` on Linux).
* **Frameworks (macOS):** The comment about "AppleFrameworks" points to the use of operating system frameworks.
* **`gnustep-config` and Makefiles:**  These are build system components, indirectly related to the final binary structure.

**7. Logical Reasoning and Examples:**

This requires thinking about how the code would behave with different inputs.

* **`GnuStepDependency` and Modules:**  If the user requests specific GnuStep modules, the `--gui-libs` or `--base-libs` flag in `gnustep-config` will change.
* **`WxDependency` and Static Linking:**  Requesting static linking changes the `wx-config` arguments and has error handling for missing static libraries.
* **`VulkanDependencySystem` and `VULKAN_SDK`:** If `VULKAN_SDK` is set, the code uses that path; otherwise, it attempts to find Vulkan in standard locations.

**8. Common User Errors:**

This involves thinking about how users might misuse the Meson build system or have their environment configured incorrectly.

* **Missing Dependencies:** If the required libraries or their development headers are not installed, the dependency detection will fail.
* **Incorrect Environment Variables:**  Setting `VULKAN_SDK` to an invalid path is a clear user error.
* **Misconfigured Build Systems:**  Not having the necessary config tools (`gnustep-config`, etc.) in the `PATH`.

**9. Tracing User Operations:**

This involves thinking about the typical build process using Meson.

* **`meson setup builddir`:** This is the command that triggers the dependency detection process.
* **Meson Configuration Files:** The `meson.build` file would contain declarations of dependencies like `dependency('gl')`.
* **Frida's Build System:**  The user is likely building Frida, and this file is part of that build process.

**Self-Correction/Refinement During the Process:**

* **Initial Over-Simplification:**  At first glance, one might think it's *just* about finding libraries. However, deeper analysis reveals the nuances of using config tools, handling different platforms, and the importance of compiler/linker flags.
* **Connecting to Frida:**  Constantly reminding myself of the context (Frida) helps to connect the code's functionality to dynamic instrumentation. The focus shifts from just "dependency management" to "dependency management *for a dynamic instrumentation tool*."
* **Specificity of Examples:**  Instead of vague examples, try to create concrete scenarios (e.g., setting `VULKAN_SDK` to a wrong path).

By following this structured approach, combining code reading with contextual understanding and reasoning, it's possible to generate a comprehensive answer that addresses all aspects of the user's request.
This Python file, `ui.py`, located within the Frida project's build system (Meson), is responsible for **detecting and configuring dependencies related to User Interface (UI) libraries** on the target system. It helps the build system find the necessary headers, libraries, and compiler/linker flags required to build Frida with UI support.

Here's a breakdown of its functionalities:

**1. Dependency Detection for UI Libraries:**

The primary function is to locate various UI-related libraries on the system. It supports:

* **OpenGL (GL):**  Detects OpenGL libraries and headers.
* **GNUstep:** Detects the GNUstep development environment (an open-source implementation of the Cocoa frameworks).
* **SDL2:** Detects the Simple DirectMedia Layer 2 library (used for multimedia and UI).
* **WxWidgets:** Detects the wxWidgets cross-platform GUI library.
* **Vulkan:** Detects the Vulkan graphics API.

**2. Providing Dependency Information to the Build System:**

Once a dependency is detected, the file provides crucial information to the Meson build system, including:

* **Include Paths (`compile_args`):** Directories where the header files of the dependency are located.
* **Library Paths and Link Libraries (`link_args`):**  Flags and paths needed to link against the dependency's libraries.
* **Version Information (`self.version`):**  Attempts to determine the version of the detected library.
* **Whether the Dependency is Found (`self.is_found`):** A boolean indicating if the dependency was successfully located.

**3. Different Detection Methods:**

The file employs various methods to detect dependencies:

* **System-Specific Locations:** For OpenGL, it checks for standard locations on macOS, Windows, and other platforms.
* **Configuration Tools (`*-config`):** For GNUstep, SDL2, and wxWidgets, it uses command-line tools like `gnustep-config`, `sdl2-config`, and `wx-config` to retrieve the necessary compiler and linker flags.
* **Environment Variables:** For Vulkan, it checks for the `VULKAN_SDK` environment variable.
* **Compiler Capabilities:** It uses the C/C++ compiler (`self.clib_compiler`) to check for the presence of header files and libraries.
* **Package Managers (Indirectly via `DependencyFactory`):**  While not directly in this file, the `DependencyFactory` suggests that other detection methods like `pkg-config` might be used implicitly.

**Relation to Reverse Engineering:**

This file, while part of the build process, has indirect relevance to reverse engineering in a few ways:

* **Identifying Dependencies:**  Reverse engineers often need to understand what libraries an application relies on. By examining how Frida detects these dependencies, a reverse engineer can get clues about the potential libraries used by applications they are analyzing. For instance, if Frida's build system detects SDL2, it suggests that Frida itself or the applications it might instrument could be using SDL2 for UI or multimedia tasks.
* **Understanding Build Environments:** Knowing how Frida is built, including its dependencies and the flags used, can be helpful in replicating build environments for analysis or modification.
* **Pinpointing UI Frameworks:** The file explicitly targets UI libraries. If a reverse engineer is analyzing an application and sees Frida interacting with UI elements, understanding how Frida itself handles UI dependencies (like wxWidgets or SDL2) can provide context.

**Examples Related to Binary Bottom, Linux, Android Kernel & Framework:**

* **Binary Bottom (OpenGL/Vulkan):** The detection of OpenGL and Vulkan directly relates to the interaction with the graphics hardware. These APIs provide low-level access to the GPU. On Linux and Android, these libraries often interface with kernel drivers (e.g., DRM/KMS on Linux, similar components on Android) to manage the display. The `link_args` will eventually lead to linking against shared objects that bridge the user-space application with the kernel's graphics subsystem.
    * **Example:** On Linux, the `self.clib_compiler.find_library('GL', ...)` call might locate `libGL.so`, which is a shared library that acts as a client-side interface to the OpenGL implementation, often involving kernel drivers for actual GPU communication.
* **Linux (General Library Detection):** The use of `self.clib_compiler.find_library()` and `self.clib_compiler.has_header()` is a common practice on Linux systems to locate shared libraries and header files in standard system directories (like `/usr/lib`, `/usr/include`, etc.).
    * **Example:** The code checks for the header `GL/gl.h` which is typically installed by OpenGL development packages on Linux.
* **Android Kernel/Framework (Indirect):** While this file doesn't directly handle Android-specific UI libraries in the same way (Android has its own framework), the principles are similar. Frida on Android might need to interact with the Android UI framework (SurfaceFlinger, View system). While this specific file might not be directly involved in detecting Android framework components, the broader Frida build system would have mechanisms to handle Android-specific dependencies and linking. The concepts of finding libraries and headers are still applicable.
* **GNUstep (Cross-Platform UI):** GNUstep is an interesting case as it provides a cross-platform implementation of the macOS Cocoa frameworks. Its detection highlights the challenges of handling UI dependencies that might have different implementations across operating systems.

**Logical Reasoning with Hypothetical Input & Output:**

Let's consider the `WxDependency` class:

**Hypothetical Input:**

```python
kwargs = {'modules': ['adv', 'core'], 'static': True}
```

**Reasoning:** The user is requesting the `adv` and `core` modules of wxWidgets and wants to link statically.

**Expected Output (if wxWidgets is found and supports static linking):**

* `self.is_found` would be `True`.
* `self.requested_modules` would be `['adv', 'core']`.
* `self.compile_args` would contain compiler flags obtained from `wx-config --cxxflags --static=yes --adv --core`.
* `self.link_args` would contain linker flags obtained from `wx-config --libs --static=yes --adv --core`.

**Expected Output (if static linking is not supported):**

* `self.is_found` would be `False` after the check `if 'No config found to match' in err:`.

**Common User/Programming Errors:**

* **Missing Development Packages:** A common error is when the user doesn't have the development packages (including headers and static libraries, if required) for a particular UI library installed. This would lead to `self.is_found` being `False`.
    * **Example:** If the user tries to build Frida and doesn't have the `libsdl2-dev` package installed on their Linux system, the `SDL2DependencyConfigTool` would likely fail to find `sdl2-config`.
* **Incorrect Environment Variables:** For Vulkan, if the `VULKAN_SDK` environment variable is set to an incorrect path, the detection will fail.
    * **Example:**  Setting `export VULKAN_SDK=/wrong/path` would cause the `VulkanDependencySystem` to raise a `DependencyException`.
* **Misconfigured Build Environment:** If the necessary configuration tools (`gnustep-config`, `sdl2-config`, `wx-config`) are not in the system's `PATH`, the corresponding dependency detection will fail.
* **Requesting Non-Existent Modules (wxWidgets):** If a user specifies a module in the `modules` keyword argument that doesn't exist for wxWidgets, the `wx-config` tool might return an error, potentially leading to build failures (though this file might not explicitly handle that error, it would be surfaced by Meson).

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **User Initiates the Frida Build Process:** The user typically starts by cloning the Frida repository and then running the Meson build system setup command:
   ```bash
   meson setup build
   ```
   or
   ```bash
   python3 meson.py setup build
   ```

2. **Meson Reads the Build Definition:** Meson reads the `meson.build` files in the Frida project, which specify the dependencies required.

3. **Dependency Declaration:**  In the `meson.build` files, there will be declarations like:
   ```python
   gl_dep = dependency('gl')
   sdl2_dep = dependency('sdl2')
   wxwidgets_dep = dependency('wxwidgets', modules: ['adv', 'core'])
   ```

4. **Meson Calls Dependency Detection Logic:** When Meson encounters a `dependency()` call, it looks up the corresponding dependency type (e.g., 'gl', 'sdl2', 'wxwidgets') and uses the associated `DependencyFactory` (defined at the end of this `ui.py` file).

5. **`DependencyFactory` Instantiates the Appropriate Class:**  The `DependencyFactory` then instantiates the relevant dependency detection class from `ui.py` (e.g., `GLDependencySystem`, `SDL2DependencyConfigTool`, `WxDependency`).

6. **The `__init__` Method is Executed:** The constructor (`__init__`) of the dependency class is called, which initiates the detection process using the methods described earlier (checking system locations, running config tools, etc.).

7. **Debugging Scenario:** If the build fails due to a missing dependency, a developer might investigate the Meson logs. These logs would show which dependency detection failed. To understand *why* it failed, a developer might then look at the source code of the specific dependency detection class in `ui.py` to understand the steps it takes and where the failure might be occurring (e.g., a config tool not being found, a header file missing, etc.). They might also manually run the configuration tools (like `wx-config --libs`) to see the output and identify issues.

Therefore, a user encountering an issue with UI dependencies during the Frida build process could trace back to this `ui.py` file to understand how those dependencies are being detected and potentially identify the root cause of the problem.

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/dependencies/ui.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2013-2017 The Meson development team

# This file contains the detection logic for external dependencies that
# are UI-related.
from __future__ import annotations

import os
import re
import subprocess
import typing as T

from .. import mlog
from .. import mesonlib
from ..compilers.compilers import CrossNoRunException
from ..mesonlib import (
    Popen_safe, extract_as_list, version_compare_many
)
from ..environment import detect_cpu_family

from .base import DependencyException, DependencyMethods, DependencyTypeName, SystemDependency
from .configtool import ConfigToolDependency
from .detect import packages
from .factory import DependencyFactory

if T.TYPE_CHECKING:
    from ..environment import Environment


class GLDependencySystem(SystemDependency):
    def __init__(self, name: str, environment: 'Environment', kwargs: T.Dict[str, T.Any]) -> None:
        super().__init__(name, environment, kwargs)

        if self.env.machines[self.for_machine].is_darwin():
            self.is_found = True
            # FIXME: Use AppleFrameworks dependency
            self.link_args = ['-framework', 'OpenGL']
            # FIXME: Detect version using self.clib_compiler
            return
        elif self.env.machines[self.for_machine].is_windows():
            self.is_found = True
            # FIXME: Use self.clib_compiler.find_library()
            self.link_args = ['-lopengl32']
            # FIXME: Detect version using self.clib_compiler
            return
        else:
            links = self.clib_compiler.find_library('GL', environment, [])
            has_header = self.clib_compiler.has_header('GL/gl.h', '', environment)[0]
            if links and has_header:
                self.is_found = True
                self.link_args = links
            elif links:
                raise DependencyException('Found GL runtime library but no development header files')

class GnuStepDependency(ConfigToolDependency):

    tools = ['gnustep-config']
    tool_name = 'gnustep-config'

    def __init__(self, environment: 'Environment', kwargs: T.Dict[str, T.Any]) -> None:
        super().__init__('gnustep', environment, kwargs, language='objc')
        if not self.is_found:
            return
        self.modules = kwargs.get('modules', [])
        self.compile_args = self.filter_args(
            self.get_config_value(['--objc-flags'], 'compile_args'))
        self.link_args = self.weird_filter(self.get_config_value(
            ['--gui-libs' if 'gui' in self.modules else '--base-libs'],
            'link_args'))

    def find_config(self, versions: T.Optional[T.List[str]] = None, returncode: int = 0) -> T.Tuple[T.Optional[T.List[str]], T.Optional[str]]:
        tool = [self.tools[0]]
        try:
            p, out = Popen_safe(tool + ['--help'])[:2]
        except (FileNotFoundError, PermissionError):
            return (None, None)
        if p.returncode != returncode:
            return (None, None)
        self.config = tool
        found_version = self.detect_version()
        if versions and not version_compare_many(found_version, versions)[0]:
            return (None, found_version)

        return (tool, found_version)

    @staticmethod
    def weird_filter(elems: T.List[str]) -> T.List[str]:
        """When building packages, the output of the enclosing Make is
        sometimes mixed among the subprocess output. I have no idea why. As a
        hack filter out everything that is not a flag.
        """
        return [e for e in elems if e.startswith('-')]

    @staticmethod
    def filter_args(args: T.List[str]) -> T.List[str]:
        """gnustep-config returns a bunch of garbage args such as -O2 and so
        on. Drop everything that is not needed.
        """
        result = []
        for f in args:
            if f.startswith('-D') \
                    or f.startswith('-f') \
                    or f.startswith('-I') \
                    or f == '-pthread' \
                    or (f.startswith('-W') and not f == '-Wall'):
                result.append(f)
        return result

    def detect_version(self) -> str:
        gmake = self.get_config_value(['--variable=GNUMAKE'], 'variable')[0]
        makefile_dir = self.get_config_value(['--variable=GNUSTEP_MAKEFILES'], 'variable')[0]
        # This Makefile has the GNUStep version set
        base_make = os.path.join(makefile_dir, 'Additional', 'base.make')
        # Print the Makefile variable passed as the argument. For instance, if
        # you run the make target `print-SOME_VARIABLE`, this will print the
        # value of the variable `SOME_VARIABLE`.
        printver = "print-%:\n\t@echo '$($*)'"
        env = os.environ.copy()
        # See base.make to understand why this is set
        env['FOUNDATION_LIB'] = 'gnu'
        p, o, e = Popen_safe([gmake, '-f', '-', '-f', base_make,
                              'print-GNUSTEP_BASE_VERSION'],
                             env=env, write=printver, stdin=subprocess.PIPE)
        version = o.strip()
        if not version:
            mlog.debug("Couldn't detect GNUStep version, falling back to '1'")
            # Fallback to setting some 1.x version
            version = '1'
        return version

packages['gnustep'] = GnuStepDependency


class SDL2DependencyConfigTool(ConfigToolDependency):

    tools = ['sdl2-config']
    tool_name = 'sdl2-config'

    def __init__(self, name: str, environment: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__(name, environment, kwargs)
        if not self.is_found:
            return
        self.compile_args = self.get_config_value(['--cflags'], 'compile_args')
        self.link_args = self.get_config_value(['--libs'], 'link_args')


class WxDependency(ConfigToolDependency):

    tools = ['wx-config-3.0', 'wx-config-3.1', 'wx-config', 'wx-config-gtk3']
    tool_name = 'wx-config'

    def __init__(self, environment: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__('WxWidgets', environment, kwargs, language='cpp')
        if not self.is_found:
            return
        self.requested_modules = self.get_requested(kwargs)

        extra_args = []
        if self.static:
            extra_args.append('--static=yes')

            # Check to make sure static is going to work
            err = Popen_safe(self.config + extra_args)[2]
            if 'No config found to match' in err:
                mlog.debug('WxWidgets is missing static libraries.')
                self.is_found = False
                return

        # wx-config seems to have a cflags as well but since it requires C++,
        # this should be good, at least for now.
        self.compile_args = self.get_config_value(['--cxxflags'] + extra_args + self.requested_modules, 'compile_args')
        self.link_args = self.get_config_value(['--libs'] + extra_args + self.requested_modules, 'link_args')

    @staticmethod
    def get_requested(kwargs: T.Dict[str, T.Any]) -> T.List[str]:
        if 'modules' not in kwargs:
            return []
        candidates = extract_as_list(kwargs, 'modules')
        for c in candidates:
            if not isinstance(c, str):
                raise DependencyException('wxwidgets module argument is not a string')
        return candidates

packages['wxwidgets'] = WxDependency

class VulkanDependencySystem(SystemDependency):

    def __init__(self, name: str, environment: 'Environment', kwargs: T.Dict[str, T.Any], language: T.Optional[str] = None) -> None:
        super().__init__(name, environment, kwargs, language=language)

        try:
            self.vulkan_sdk = os.environ['VULKAN_SDK']
            if not os.path.isabs(self.vulkan_sdk):
                raise DependencyException('VULKAN_SDK must be an absolute path.')
        except KeyError:
            self.vulkan_sdk = None

        if self.vulkan_sdk:
            # TODO: this config might not work on some platforms, fix bugs as reported
            # we should at least detect other 64-bit platforms (e.g. armv8)
            lib_name = 'vulkan'
            lib_dir = 'lib'
            inc_dir = 'include'
            if mesonlib.is_windows():
                lib_name = 'vulkan-1'
                lib_dir = 'Lib32'
                inc_dir = 'Include'
                if detect_cpu_family(self.env.coredata.compilers.host) == 'x86_64':
                    lib_dir = 'Lib'

            # make sure header and lib are valid
            inc_path = os.path.join(self.vulkan_sdk, inc_dir)
            header = os.path.join(inc_path, 'vulkan', 'vulkan.h')
            lib_path = os.path.join(self.vulkan_sdk, lib_dir)
            find_lib = self.clib_compiler.find_library(lib_name, environment, [lib_path])

            if not find_lib:
                raise DependencyException('VULKAN_SDK point to invalid directory (no lib)')

            if not os.path.isfile(header):
                raise DependencyException('VULKAN_SDK point to invalid directory (no include)')

            # XXX: this is very odd, and may deserve being removed
            self.type_name = DependencyTypeName('vulkan_sdk')
            self.is_found = True
            self.compile_args.append('-I' + inc_path)
            self.link_args.append('-L' + lib_path)
            self.link_args.append('-l' + lib_name)
        else:
            # simply try to guess it, usually works on linux
            libs = self.clib_compiler.find_library('vulkan', environment, [])
            if libs is not None and self.clib_compiler.has_header('vulkan/vulkan.h', '', environment, disable_cache=True)[0]:
                self.is_found = True
                for lib in libs:
                    self.link_args.append(lib)

        if self.is_found:
            get_version = '''\
#include <stdio.h>
#include <vulkan/vulkan.h>

int main() {
    printf("%i.%i.%i", VK_VERSION_MAJOR(VK_HEADER_VERSION_COMPLETE),
                       VK_VERSION_MINOR(VK_HEADER_VERSION_COMPLETE),
                       VK_VERSION_PATCH(VK_HEADER_VERSION_COMPLETE));
    return 0;
}
'''
            try:
                run = self.clib_compiler.run(get_version, environment, extra_args=self.compile_args)
            except CrossNoRunException:
                run = None
            if run and run.compiled and run.returncode == 0:
                self.version = run.stdout
            elif self.vulkan_sdk:
                # fall back to heuristics: detect version number in path
                # matches the default install path on Windows
                match = re.search(rf'VulkanSDK{re.escape(os.path.sep)}([0-9]+(?:\.[0-9]+)+)', self.vulkan_sdk)
                if match:
                    self.version = match.group(1)
                else:
                    mlog.warning(f'Environment variable VULKAN_SDK={self.vulkan_sdk} is present, but Vulkan version could not be extracted.')

packages['gl'] = gl_factory = DependencyFactory(
    'gl',
    [DependencyMethods.PKGCONFIG, DependencyMethods.SYSTEM],
    system_class=GLDependencySystem,
)

packages['sdl2'] = sdl2_factory = DependencyFactory(
    'sdl2',
    [DependencyMethods.PKGCONFIG, DependencyMethods.CONFIG_TOOL, DependencyMethods.EXTRAFRAMEWORK, DependencyMethods.CMAKE],
    configtool_class=SDL2DependencyConfigTool,
    cmake_name='SDL2',
)

packages['vulkan'] = vulkan_factory = DependencyFactory(
    'vulkan',
    [DependencyMethods.PKGCONFIG, DependencyMethods.SYSTEM],
    system_class=VulkanDependencySystem,
)

"""

```