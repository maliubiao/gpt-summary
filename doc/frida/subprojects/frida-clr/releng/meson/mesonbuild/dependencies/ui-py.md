Response:
My thinking process to analyze the Python code and answer the prompt went something like this:

1. **Understand the Goal:** The request asks for a breakdown of the code's functionality, its relation to reverse engineering, low-level aspects, logical reasoning, common user errors, and how a user might end up interacting with it. Essentially, I need to interpret the code's purpose within the larger Frida context.

2. **High-Level Overview:** I first scanned the code to identify its primary function. The file name (`ui.py`) and the import of `DependencyFactory` and various `Dependency` classes strongly suggest this code is responsible for detecting and configuring UI-related external dependencies for the Frida build process. Meson's role as a build system is crucial here.

3. **Analyze Individual Dependency Classes:** I then examined each dependency class (`GLDependencySystem`, `GnuStepDependency`, `SDL2DependencyConfigTool`, `WxDependency`, `VulkanDependencySystem`) individually:

    * **Identify the Target Library:** What UI library is each class responsible for? (OpenGL, GNUstep, SDL2, wxWidgets, Vulkan).
    * **Detection Methods:** How does it try to find the library? (System paths, `pkg-config`, specific config tools like `sdl2-config`, environment variables like `VULKAN_SDK`).
    * **Configuration:** What compiler and linker flags are set based on the detection? (`compile_args`, `link_args`).
    * **Platform Specifics:** Are there platform-specific checks (e.g., macOS `-framework OpenGL`, Windows `-lopengl32`)?
    * **Version Detection:** Does it attempt to determine the library version? How? (config tools, header files, environment variables).
    * **Error Handling:** Are there specific error conditions handled (e.g., missing headers, static library issues)?

4. **Identify Common Themes and Patterns:** I looked for recurring patterns in how dependencies are handled:

    * **`DependencyFactory`:** This is the core mechanism for registering dependencies and their detection methods.
    * **`SystemDependency` vs. `ConfigToolDependency`:**  Recognizing these base classes helped me categorize the detection strategies.
    * **`compile_args` and `link_args`:** These are consistently used to propagate the necessary compiler and linker settings.

5. **Relate to Reverse Engineering:** This is where I had to connect the dots between UI libraries and reverse engineering. I considered how these libraries are used in applications that might be targeted by Frida:

    * **UI Interaction:** Libraries like SDL2 and wxWidgets are directly used for creating graphical user interfaces. Frida might be used to inspect or modify UI elements.
    * **Graphics Rendering:** OpenGL and Vulkan are used for rendering graphics, which is relevant for games or applications with custom rendering engines. Frida could be used to analyze rendering logic or inject custom rendering.
    * **GNUstep:**  While less common nowadays, its historical relevance in macOS-like environments is still important.

6. **Address Low-Level Aspects:** I looked for code elements that hinted at interaction with the underlying system:

    * **Kernel/Framework:** Direct use of system frameworks on macOS (`-framework OpenGL`).
    * **Binary Libraries:** Linking against specific `.so` or `.dll` files (`-lopengl32`, `vulkan`).
    * **Environment Variables:** Relying on `VULKAN_SDK`.
    * **System Calls (Implicit):**  While not directly visible, the act of linking libraries implies interaction with the OS loader.

7. **Analyze Logical Reasoning:**  I looked for conditional logic and assumptions:

    * **Platform Detection:** The `is_darwin()`, `is_windows()` checks are key examples of branching logic based on the target OS.
    * **Version Comparison:** The use of `version_compare_many`.
    * **Static Linking Checks:** The `WxDependency` class explicitly checks if static linking is possible.

8. **Consider User Errors:** I thought about how a user configuring a Frida build might encounter issues:

    * **Missing Dependencies:** Not having the required development packages installed.
    * **Incorrect Paths:**  Setting `VULKAN_SDK` to an invalid path.
    * **Conflicting Configurations:** Trying to statically link wxWidgets when static libraries aren't available.

9. **Trace User Interaction:** I imagined the steps a user would take to trigger this code:

    * **Configuring the Build:**  Running Meson to configure the Frida build.
    * **Dependency Declarations:**  Frida's `meson.build` files would declare dependencies on these UI libraries.
    * **Meson's Dependency Resolution:** Meson would call these dependency detection functions during the configuration process.

10. **Structure the Answer:** Finally, I organized my findings into the categories requested by the prompt, providing specific code examples and explanations for each point. I aimed for clarity and conciseness.

By following this structured approach, I was able to systematically analyze the code and provide a comprehensive answer that addresses all aspects of the prompt. The key was to understand the code's role within the Meson build system and then connect the specific functionalities to the broader context of Frida and reverse engineering.
这个文件 `ui.py` 是 Frida 动态 instrumentation 工具构建系统的一部分，它使用 Meson 构建系统来处理与用户界面 (UI) 相关的外部依赖项。 它的主要功能是检测系统中是否存在特定的 UI 库，并为 Frida 构建过程提供必要的编译和链接参数。

以下是该文件的功能列表，并根据你的要求进行了详细说明：

**1. 依赖项检测和配置:**

* **功能:**  该文件定义了多个类，每个类负责检测和配置一个特定的 UI 依赖项，例如 OpenGL, GNUstep, SDL2, wxWidgets 和 Vulkan。
* **工作原理:**  这些类会尝试在系统中查找所需的库和头文件。它们通常会使用以下方法：
    * **系统路径搜索:** 查找标准库路径。
    * **`pkg-config`:**  使用 `pkg-config` 工具获取库的编译和链接信息。
    * **特定配置工具:**  使用特定于库的配置工具，如 `sdl2-config` 和 `wx-config`。
    * **环境变量:**  检查特定的环境变量，例如 `VULKAN_SDK`。
    * **编译测试:**  尝试编译简单的代码片段来检查头文件是否存在。
* **输出:** 如果找到依赖项，这些类会设置 `is_found` 属性为 `True`，并生成 `compile_args` (编译参数，如头文件路径) 和 `link_args` (链接参数，如库文件路径和名称)。

**2. 与逆向方法的关联 (举例说明):**

* **功能:**  这些 UI 库通常被目标应用程序使用，Frida 可以通过 hook 这些库的函数来拦截和修改应用程序的行为。
* **举例说明 (OpenGL):**
    * **假设:** 你想逆向一个使用 OpenGL 进行渲染的游戏。
    * **Frida 的作用:**  通过 hook OpenGL 的 `glDrawArrays` 或 `glBegin`/`glEnd` 等函数，你可以拦截游戏的渲染调用，从而：
        * **查看渲染参数:**  获取顶点数据、纹理信息等，了解游戏如何绘制场景。
        * **修改渲染结果:**  修改顶点坐标、颜色等，实现透视、物体替换等效果。
        * **性能分析:**  统计渲染调用的次数和耗时，分析性能瓶颈。
    * **`ui.py` 的作用:**  确保 Frida 构建时能够正确链接 OpenGL 库，使得 Frida 能够顺利 hook OpenGL 相关函数。
* **举例说明 (SDL2):**
    * **假设:** 你想逆向一个使用 SDL2 创建窗口和处理事件的应用程序。
    * **Frida 的作用:**  通过 hook SDL2 的 `SDL_CreateWindow`、`SDL_PollEvent` 等函数，你可以：
        * **拦截窗口创建:**  阻止窗口创建，或者修改窗口属性。
        * **监控事件:**  记录用户的键盘输入、鼠标点击等事件。
        * **模拟事件:**  向应用程序发送自定义的事件。
    * **`ui.py` 的作用:**  确保 Frida 构建时能够正确链接 SDL2 库，使得 Frida 能够 hook SDL2 相关函数。

**3. 涉及到二进制底层，Linux, Android 内核及框架的知识 (举例说明):**

* **功能:**  虽然这个 `ui.py` 文件本身主要是关于构建配置，但它所配置的依赖项与底层的交互非常密切。
* **举例说明 (Linux 和 Android):**
    * **OpenGL/Vulkan 驱动:**  在 Linux 和 Android 上，OpenGL 和 Vulkan 的实现依赖于底层的图形驱动程序，这些驱动程序直接与硬件交互。Frida hook 这些库的调用实际上是在与内核或用户空间的驱动程序代码进行交互。
    * **动态链接:**  Frida 需要将自身注入到目标进程中，并 hook 目标进程调用的库函数。这涉及到操作系统的动态链接机制，例如 Linux 的 `ld-linux.so` 和 Android 的 `linker`。`ui.py` 中配置的链接参数确保 Frida 能够找到这些 UI 库的二进制文件 (`.so` 文件)。
    * **Android 框架:**  在 Android 上，UI 相关的操作通常会涉及到 Android Framework 的组件，例如 SurfaceFlinger (负责屏幕合成)。虽然 `ui.py` 直接处理的是 OpenGL 和 Vulkan 等库，但理解 Android 框架有助于进行更深入的逆向分析。
* **`GLDependencySystem` 的平台特定处理:**  代码中针对 Darwin (macOS) 和 Windows 平台硬编码了 OpenGL 的链接参数 (`-framework OpenGL` 和 `-lopengl32`)，这体现了不同操作系统下库的链接方式的差异，属于操作系统底层的知识。

**4. 逻辑推理 (假设输入与输出):**

* **假设输入:** 用户在 Linux 系统上构建 Frida，并且系统中已经安装了 OpenGL 开发库 (例如 `libgl-dev` 包)。
* **`GLDependencySystem` 的推理:**
    1. 代码会尝试使用 `self.clib_compiler.find_library('GL', environment, [])` 查找名为 `GL` 的库。
    2. 如果找到库文件 (例如 `libGL.so`)，则 `links` 变量会包含库文件的路径。
    3. 代码会检查是否存在头文件 `GL/gl.h`。
    4. **输出:** 如果库文件和头文件都找到，`self.is_found` 将被设置为 `True`，并且 `self.link_args` 将包含找到的库文件路径，例如 `['-lGL']` (取决于 `find_library` 的具体实现)。
* **假设输入:** 用户在 Windows 系统上构建 Frida。
* **`GLDependencySystem` 的推理:**
    1. 代码会进入 `elif self.env.machines[self.for_machine].is_windows():` 分支。
    2. 代码直接设置 `self.is_found = True` 和 `self.link_args = ['-lopengl32']`。
    3. **输出:** `self.is_found` 为 `True`，`self.link_args` 为 `['-lopengl32']`。这里没有实际的库查找，而是假定 OpenGL32.dll 存在于标准系统路径中。

**5. 用户或编程常见的使用错误 (举例说明):**

* **缺少依赖库:**
    * **错误:**  用户在构建 Frida 之前，没有安装所需的 UI 库的开发包 (例如，在 Ubuntu 上没有安装 `libsdl2-dev`)。
    * **`ui.py` 的影响:**  相关的依赖项类 (例如 `SDL2DependencyConfigTool`) 将无法找到库文件或头文件，导致 `self.is_found` 为 `False`。
    * **构建失败:**  Meson 构建系统会报错，提示找不到所需的依赖项。
* **环境变量配置错误:**
    * **错误:**  用户设置了 `VULKAN_SDK` 环境变量，但指向的路径不正确，或者该路径下缺少必要的头文件或库文件。
    * **`VulkanDependencySystem` 的影响:**  代码会抛出 `DependencyException`，例如 "VULKAN_SDK point to invalid directory (no lib)" 或 "VULKAN_SDK point to invalid directory (no include)"。
    * **构建失败:**  Meson 构建系统会因为依赖项错误而中止。
* **wxWidgets 静态链接问题:**
    * **错误:**  用户尝试静态链接 wxWidgets (通过 `static: true` 参数)，但系统中没有编译好的静态库版本。
    * **`WxDependency` 的影响:**  `Popen_safe(self.config + extra_args)[2]` 会返回错误信息，包含 "No config found to match"。
    * **逻辑:**  `if 'No config found to match' in err:`  这个条件会判断出来，并将 `self.is_found` 设置为 `False`。
    * **构建失败或回退:**  构建可能会失败，或者 Meson 会尝试寻找其他满足条件的 wxWidgets 配置。

**6. 用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户尝试构建 Frida:** 用户通常会执行类似 `meson setup build` 或 `ninja` 命令来构建 Frida。
2. **Meson 解析构建文件:** Meson 读取 Frida 的 `meson.build` 文件，这些文件声明了 Frida 的依赖项，包括 UI 相关的依赖项 (例如，通过 `dependency('sdl2')`)。
3. **Meson 调用依赖项工厂:**  当 Meson 遇到 `dependency('sdl2')` 时，它会查找与 `sdl2` 关联的 `DependencyFactory` (在本例中是 `sdl2_factory`)。
4. **工厂尝试不同的检测方法:** `sdl2_factory` 定义了尝试的检测方法顺序：`[DependencyMethods.PKGCONFIG, DependencyMethods.CONFIG_TOOL, DependencyMethods.EXTRAFRAMEWORK, DependencyMethods.CMAKE]`。
5. **执行 `SDL2DependencyConfigTool`:** 如果 `pkg-config` 没有找到 SDL2，Meson 可能会尝试使用 `DependencyMethods.CONFIG_TOOL`，这将导致实例化 `SDL2DependencyConfigTool` 类。
6. **`SDL2DependencyConfigTool` 运行 `sdl2-config`:**  `SDL2DependencyConfigTool` 的 `__init__` 方法会尝试运行 `sdl2-config --cflags` 和 `sdl2-config --libs` 来获取编译和链接参数。
7. **结果返回给 Meson:**  `SDL2DependencyConfigTool` 的 `compile_args` 和 `link_args` 属性会被 Meson 使用来配置编译器的命令行。

**调试线索:**

* **查看 Meson 的配置输出:**  Meson 在配置过程中会打印出尝试检测依赖项的信息，例如 "Found sdl2 dependency via pkgconfig" 或 "Trying to find sdl2 using sdl2-config"。这些信息可以帮助你了解 Meson 使用了哪些检测方法以及是否成功。
* **检查构建日志:**  如果构建失败，查看详细的构建日志，通常会包含编译器和链接器的错误信息，可以帮助你定位是哪个依赖项出了问题。
* **手动运行配置工具:**  你可以尝试手动运行 `sdl2-config --cflags` 和 `sdl2-config --libs` 等命令，看看是否能正常输出，以及输出的路径是否正确。
* **检查环境变量:**  如果依赖项检测涉及到环境变量，例如 `VULKAN_SDK`，请确保该变量已正确设置。

总而言之，`ui.py` 文件在 Frida 的构建过程中扮演着关键的角色，它负责识别和配置构建 UI 相关功能的必要条件。理解这个文件的功能有助于理解 Frida 如何处理外部依赖，并为调试构建问题提供线索，尤其是在涉及到 UI 功能时。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/dependencies/ui.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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