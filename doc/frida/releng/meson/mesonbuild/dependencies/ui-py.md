Response:
Let's break down the thought process for analyzing the provided Python code.

1. **Understand the Core Purpose:** The file resides within `frida/releng/meson/mesonbuild/dependencies/ui.py`. The `dependencies` part strongly suggests it's about managing external software components required by Frida during its build process. The `ui.py` part hints that these dependencies are related to user interface or graphical aspects.

2. **Identify Key Classes:**  A quick scan reveals several classes: `GLDependencySystem`, `GnuStepDependency`, `SDL2DependencyConfigTool`, `WxDependency`, and `VulkanDependencySystem`. These are the primary actors. The names themselves give strong clues about the UI libraries they handle (OpenGL, GnuStep, SDL2, WxWidgets, Vulkan).

3. **Analyze Each Class Individually:**  For each class, consider:
    * **Inheritance:** What base class does it inherit from? (`SystemDependency`, `ConfigToolDependency`). This tells us the general mechanism it uses to find the dependency.
    * **Initialization (`__init__`)**: What are the key steps taken during initialization?  Are there platform-specific checks (e.g., `is_darwin()`, `is_windows()`)? Are there environment variable lookups (e.g., `VULKAN_SDK`)?
    * **Finding the Dependency:** How does it actually locate the library?  Does it use:
        * **System paths:**  Checking standard library locations (implicit in `SystemDependency`).
        * **Configuration tools:** Using tools like `sdl2-config`, `wx-config`.
        * **Environment variables:**  Like `VULKAN_SDK`.
        * **Specific file checks:** Looking for headers (`GL/gl.h`, `vulkan/vulkan.h`).
        * **Compiler features:**  Using `clib_compiler.find_library()` and `clib_compiler.has_header()`.
    * **Collecting Information:** What information does it gather about the dependency? (compile flags, link flags, version).
    * **Error Handling:** Does it raise specific exceptions (`DependencyException`) if something goes wrong?

4. **Look for Patterns and Common Themes:** Notice the recurring use of `clib_compiler` for finding libraries and headers. Observe the common structure of `ConfigToolDependency` classes.

5. **Connect to Reverse Engineering Concepts:**  Think about how these UI libraries are relevant to reverse engineering. Frida is used to interact with and modify running processes. If a target application has a graphical interface, Frida might need to interact with the UI framework. This is where the dependencies come in. Consider specific examples like injecting a UI element or intercepting UI events.

6. **Relate to Low-Level Concepts:** Consider how UI libraries interact with the operating system kernel and underlying hardware. OpenGL and Vulkan directly interact with the graphics processing unit (GPU). Think about the role of device drivers and system calls.

7. **Identify Logical Reasoning:**  Focus on conditional statements (`if`, `elif`, `else`) and loops. For example, the logic in `GLDependencySystem` checks for macOS, Windows, and then other platforms. The `VulkanDependencySystem` prioritizes the `VULKAN_SDK` environment variable.

8. **Consider User Errors:** Think about common mistakes a user might make during the build process or when using Frida with targets that rely on these UI libraries. Incorrect environment variables, missing development packages, or using incompatible versions are potential issues.

9. **Trace the User Journey (Debugging Perspective):** Imagine a scenario where a dependency is not found. How would the user or a developer arrive at this code? They might be:
    * Running the Meson build system.
    * Encountering an error message related to a missing UI dependency.
    * Examining the build logs.
    * Potentially stepping through the Meson build scripts or this specific Python file during debugging.

10. **Structure the Answer:** Organize the findings into logical sections: Functional Overview, Relationship to Reversing, Low-Level Concepts, Logical Reasoning, User Errors, and Debugging Clues. Use clear examples and explanations.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file *implements* the UI?  **Correction:** The filenames and the nature of the code clearly indicate it's about *detecting and managing* external UI libraries, not implementing them.
* **Overly technical:**  Focusing too much on internal Meson details. **Correction:**  Shift the focus to the purpose and functionality related to Frida and the external dependencies. Explain Meson concepts only when necessary.
* **Vague connections to reversing:**  Simply stating "it's used for UI." **Correction:** Provide concrete examples of how these UI libraries are relevant in a reverse engineering context (e.g., interacting with game UIs, analyzing graphical applications).
* **Insufficient examples:**  Listing features without demonstrating them. **Correction:**  Add illustrative examples for logical reasoning and user errors.

By following these steps, systematically analyzing the code, and considering the context of Frida and reverse engineering, we can arrive at a comprehensive understanding of the provided Python file.
这个Python文件 `ui.py` 是 Frida 动态 Instrumentation 工具中 Meson 构建系统的一部分，负责检测和配置与用户界面（UI）相关的外部依赖库。它的主要功能是：

**1. 检测系统上是否存在特定的 UI 库:**

   - **OpenGL (`GLDependencySystem`):** 检测系统上是否安装了 OpenGL 库。它会根据不同的操作系统（macOS, Windows, Linux等）采用不同的检测方法。
   - **GNUstep (`GnuStepDependency`):** 检测 GNUstep 开发环境，这是一个开源的 Cocoa 实现。
   - **SDL2 (`SDL2DependencyConfigTool`):** 检测 Simple DirectMedia Layer 2 (SDL2) 库，一个跨平台的多媒体库。
   - **WxWidgets (`WxDependency`):** 检测 WxWidgets 库，一个跨平台的 C++ GUI 工具包。
   - **Vulkan (`VulkanDependencySystem`):** 检测 Vulkan 图形 API 库。

**2. 获取依赖库的编译和链接参数:**

   - 对于每个检测到的库，它会尝试获取编译所需的头文件路径 (`compile_args`) 和链接所需的库文件路径或链接器参数 (`link_args`)。
   - 它会使用不同的方法来获取这些参数，例如：
     - **系统默认路径:** 在标准系统路径中查找库文件。
     - **配置文件 (`ConfigToolDependency`):** 使用像 `sdl2-config` 或 `wx-config` 这样的工具来获取编译和链接信息。
     - **环境变量:** 例如，`VulkanDependencySystem` 会检查 `VULKAN_SDK` 环境变量。
     - **硬编码路径 (作为回退):** 对于某些平台和库，可能会使用硬编码的路径或链接参数作为一种回退方案。

**3. 处理平台差异:**

   - 代码中存在大量的平台特定的逻辑（例如，对 macOS、Windows 和 Linux 的不同处理）。
   - 不同的操作系统有不同的库命名约定、文件路径和获取依赖信息的方式，这段代码需要处理这些差异。

**4. 版本检测 (部分):**

   - 对于 GNUstep，代码尝试通过运行 `gnustep-config` 和解析其输出来检测版本。
   - 对于 Vulkan，代码尝试编译一个简单的程序来获取 Vulkan 头文件的版本。

**5. 提供依赖项信息给 Meson 构建系统:**

   - 这些类都继承自 `SystemDependency` 或 `ConfigToolDependency`，它们提供了一个统一的接口，Meson 可以使用这个接口来获取依赖项的信息，并将其集成到构建过程中。

**与逆向方法的关系及举例说明:**

这个文件本身不直接执行逆向操作，但它为 Frida 的构建提供了必要的 UI 库支持。Frida 作为一个动态 Instrumentation 工具，经常被用于逆向工程，因为它允许在运行时检查和修改应用程序的行为。

**举例说明:**

假设你想使用 Frida 来 hook 一个使用 SDL2 库进行图形渲染的游戏。为了 Frida 能够成功构建，`ui.py` 文件中的 `SDL2DependencyConfigTool` 类需要能够正确地检测到你系统上安装的 SDL2 库，并获取其编译和链接参数。

在 Frida 的构建过程中，Meson 会调用 `SDL2DependencyConfigTool`，它会执行 `sdl2-config --cflags` 和 `sdl2-config --libs` 命令来获取 SDL2 的头文件路径和库文件路径。这些信息会被传递给编译器和链接器，确保 Frida 能够正确地链接到 SDL2 库。

**涉及到二进制底层，Linux, Android 内核及框架的知识的举例说明:**

- **二进制底层:** 链接器参数（例如 `-lGL`, `-lopengl32`）直接操作二进制文件的链接过程，告诉链接器需要链接哪些库文件。
- **Linux:** 在 Linux 系统上，查找库文件通常涉及到检查 `/usr/lib`, `/usr/local/lib` 等标准路径，以及使用 `pkg-config` 工具。 `ui.py` 中的代码会尝试使用这些机制来找到 OpenGL 和 Vulkan 等库。
- **Android 内核及框架:** 虽然这个文件本身没有直接涉及到 Android 内核，但 Frida 经常被用于 Android 平台的逆向分析。Android 系统也使用了 OpenGL (OpenGL ES) 和 Vulkan 进行图形渲染。如果 Frida 需要构建在 Android 上并 hook 使用这些图形 API 的应用，那么这个文件中的 `GLDependencySystem` 和 `VulkanDependencySystem` 的逻辑就需要能够适应 Android 的环境（尽管可能需要额外的配置或专门的 Android 构建脚本）。
- **文件路径:** 代码中使用了 `os.path.join` 来构建跨平台的文件路径，这与操作系统底层的路径结构直接相关。

**逻辑推理，假设输入与输出:**

**假设输入:**

1. 操作系统是 Ubuntu Linux。
2. 系统上安装了 OpenGL 开发包 (`libgl-dev`)。

**GLDependencySystem 的逻辑推理:**

-  `self.env.machines[self.for_machine].is_darwin()` 为 `False`。
-  `self.env.machines[self.for_machine].is_windows()` 为 `False`。
-  `self.clib_compiler.find_library('GL', environment, [])` 将会在系统的库路径中找到 `libGL.so` 或类似的库文件，返回包含该库文件路径的列表。
-  `self.clib_compiler.has_header('GL/gl.h', '', environment)[0]` 将会找到 `GL/gl.h` 头文件，返回 `True`。
-  因此，`self.is_found` 将被设置为 `True`。
-  `self.link_args` 将被设置为包含 `libGL.so` 路径的列表（例如 `['-lGL']`，具体取决于 `find_library` 的实现）。

**假设输出 (GLDependencySystem):**

```python
self.is_found = True
self.link_args = ['-lGL'] # 或者其他表示找到 GL 库的链接参数
```

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **缺少开发包:** 用户可能安装了 OpenGL 或 SDL2 的运行时库，但没有安装开发包（包含头文件）。例如，在 Debian/Ubuntu 上，用户可能安装了 `libgl1` 但没有安装 `libgl-dev`。在这种情况下，`GLDependencySystem` 可能会找到运行时库，但 `has_header` 检查会失败，导致抛出 `DependencyException('Found GL runtime library but no development header files')`。
2. **环境变量未设置或设置错误:** 对于 Vulkan，如果用户没有设置 `VULKAN_SDK` 环境变量，或者设置的路径不正确，`VulkanDependencySystem` 可能无法找到 Vulkan SDK。即使设置了，如果路径指向了一个不包含必要的 `lib` 和 `include` 目录的 SDK，也会导致错误。
3. **配置工具不存在或不在 PATH 中:** 对于 SDL2 和 WxWidgets，如果 `sdl2-config` 或 `wx-config` 工具没有安装或不在系统的 PATH 环境变量中，`ConfigToolDependency` 将无法找到这些工具，导致依赖项检测失败。
4. **指定了错误的模块名:** 对于 WxWidgets，用户在使用 `modules` 参数时可能会拼写错误模块名，导致 `wx-config` 找不到对应的模块。
5. **尝试静态链接但静态库不存在:** 对于 WxWidgets，如果用户尝试使用 `static=True` 进行静态链接，但系统上没有编译好的静态库，构建将会失败。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在构建 Frida 时遇到了关于 SDL2 依赖的错误。以下是可能的用户操作路径：

1. **用户尝试构建 Frida:** 用户按照 Frida 的文档或教程，执行构建命令，例如 `meson setup _build` 或 `ninja -C _build`。
2. **Meson 开始配置构建:** Meson 构建系统开始运行，读取 `meson.build` 文件，并解析项目依赖。
3. **检测 SDL2 依赖:** Meson 遇到需要 SDL2 的组件，会调用 `frida/releng/meson/mesonbuild/dependencies/ui.py` 文件中的 `SDL2DependencyConfigTool` 类。
4. **执行 `sdl2-config`:** `SDL2DependencyConfigTool` 尝试执行 `sdl2-config --cflags` 和 `sdl2-config --libs` 命令。
5. **可能出现的问题:**
    - **`sdl2-config` 未找到:** 如果 SDL2 的开发包没有安装，或者 `sdl2-config` 不在 PATH 中，`Popen_safe` 会抛出 `FileNotFoundError`，导致 `self.is_found` 为 `False`。
    - **`sdl2-config` 返回错误:** 如果 `sdl2-config` 存在但返回错误（例如，SDL2 安装不完整），`Popen_safe` 的返回码不为 0，也会导致 `self.is_found` 为 `False`。
    - **获取的编译/链接参数错误:**  即使 `sdl2-config` 运行成功，但如果返回的参数不正确，后续的编译或链接步骤可能会失败。
6. **Meson 报告错误:** 如果 `SDL2DependencyConfigTool` 无法找到 SDL2 或获取到正确的参数，Meson 会报告一个关于缺少 SDL2 依赖的错误，并停止构建过程。

**作为调试线索:**

当用户报告 SDL2 相关的构建错误时，开发者可以：

-   **检查用户的构建日志:** 查看 Meson 的输出，确认是否报告了找不到 `sdl2-config` 或 SDL2 库的错误。
-   **让用户检查 `sdl2-config` 是否安装且在 PATH 中:** 指导用户在命令行执行 `sdl2-config --version`，看是否能够正常输出版本信息。
-   **让用户检查 SDL2 开发包是否已安装:**  根据用户的操作系统，指导用户检查是否安装了类似 `libsdl2-dev` 的开发包。
-   **手动执行 `sdl2-config --cflags` 和 `sdl2-config --libs`:**  在用户的环境下手动执行这些命令，查看输出结果，判断 `sdl2-config` 是否工作正常，以及返回的参数是否合理。
-   **查看 `ui.py` 的代码:** 理解 `SDL2DependencyConfigTool` 的实现逻辑，可以帮助定位问题是在哪个环节出错（例如，`Popen_safe` 失败，或者获取到的参数为空）。

总而言之，`frida/releng/meson/mesonbuild/dependencies/ui.py` 文件在 Frida 的构建过程中扮演着关键角色，它负责检测和配置与 UI 相关的外部依赖，确保 Frida 能够正确地链接到这些库，从而支持对使用了这些 UI 库的目标应用程序进行动态 instrumentation 和逆向分析。理解这个文件的功能和实现方式，对于调试 Frida 的构建问题以及理解 Frida 的依赖关系至关重要。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/dependencies/ui.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```