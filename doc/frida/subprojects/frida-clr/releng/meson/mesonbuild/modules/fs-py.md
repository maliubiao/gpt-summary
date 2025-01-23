Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Core Purpose:** The very first line, `这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/modules/fs.py的fridaDynamic instrumentation tool的源代码文件`, immediately tells us this is about file system operations within the context of the Frida dynamic instrumentation tool, specifically using the Meson build system. This sets the stage for everything else. We know we're dealing with build processes, file manipulation, and likely some interaction with the underlying OS.

2. **Identify Key Classes and Functions:**  Scanning the code, the `FSModule` class stands out. Its methods (like `copyfile`, `exists`, `read`, etc.) are clearly the core functionalities being offered. We should list these out.

3. **Analyze Individual Functions:** For each method in `FSModule`, ask:
    * **What does it do?**  Look at the method name and its docstring (if present). The code itself also gives clues. For example, `exists` likely checks if a file exists. `copyfile` copies a file.
    * **What are its inputs and outputs?**  Pay attention to the function arguments and the return type. Are there any type hints?  What data types are being manipulated (strings, files, build targets)?
    * **Are there any special considerations or error handling?**  Look for `try...except` blocks, conditional statements, and specific checks (e.g., checking if a file is a directory before hashing).
    * **Does it interact with external libraries or OS functions?**  Look for imports like `os`, `hashlib`, `pathlib`.

4. **Look for Connections to Reverse Engineering:**  Think about how file system operations are relevant to reverse engineering.
    * **Reading files:**  Reverse engineers often need to read configuration files, data files, or even parts of the target application's files.
    * **Copying files:**  Useful for creating backups, moving files to analysis environments, or preparing files for modification.
    * **Hashing files:**  Essential for verifying file integrity and identifying specific versions of files.
    * **Checking file existence and properties:**  Helps in understanding the application's file structure and dependencies.

5. **Consider Low-Level and Kernel/Framework Aspects:** Since Frida is an instrumentation tool, think about its relationship to the operating system.
    * **File paths:**  The module deals with file paths, which are fundamental to how the OS organizes files. Concepts like absolute vs. relative paths, symbolic links, and path separators are relevant.
    * **File metadata:**  Functions like `size` and the use of `file.stat()` hint at accessing file metadata managed by the OS kernel.
    * **Build processes:**  The context of Meson implies that these file operations are part of a build system, which manages the compilation and linking of software. This indirectly involves understanding how software interacts with the OS.
    * **Android:** Since Frida is mentioned, and Android is a common target for Frida, consider how file systems work on Android (permissions, locations of important files, etc.). While this specific code doesn't directly manipulate Android kernel internals, it provides building blocks for tools that might.

6. **Identify Logical Reasoning and Assumptions:**
    * **Path resolution:** The module makes decisions about how to resolve relative paths and handle symbolic links. Consider scenarios where these assumptions might lead to unexpected behavior.
    * **Error handling:**  The `try...except` blocks show where the code anticipates potential errors and how it handles them.

7. **Think about User Errors:**  Based on the function parameters and error handling, identify common mistakes a user might make.
    * **Incorrect file paths:** Providing a non-existent path is a classic error.
    * **Trying to hash a directory:** The code explicitly checks for this.
    * **Forgetting `install_dir` when installing:** The `copyfile` function enforces this.
    * **Providing build directory paths to `fs.read`:**  This is intentionally blocked to prevent build loops.

8. **Trace User Operations:**  Consider how a user might end up using these functions. The context of Meson build files (`meson.build`) is key. Imagine a scenario where a developer wants to copy a configuration file into the build directory or read the version number from a file.

9. **Structure the Answer:** Organize the findings into logical categories like "Functionality," "Relationship to Reverse Engineering," "Low-Level/Kernel Aspects," "Logical Reasoning," "User Errors," and "Debugging Clues."  Use clear and concise language. Provide specific examples where possible.

10. **Review and Refine:**  Read through the analysis to ensure accuracy, completeness, and clarity. Are there any ambiguities or areas that could be explained better?  Did you miss any important details?  For example, initially, I might not have explicitly linked `fs.read` to the potential reading of sensitive information in reverse engineering. A review would help to make these connections more explicit.
这是一个名为 `fs.py` 的 Python 源代码文件，它属于 Frida 动态 instrumentation 工具项目的一部分，位于 Meson 构建系统的模块目录下。该模块旨在提供文件系统相关的操作功能，供 Frida 的构建脚本使用。

**功能列表：**

该模块提供了一系列用于操作文件和路径的功能，可以大致归类如下：

1. **路径处理:**
   - `as_posix(path)`: 将 Windows 风格的路径转换为 POSIX 风格的路径。
   - `expanduser(path)`: 展开路径中的 `~` 或 `~user` 为用户目录。
   - `is_absolute(path)`: 判断路径是否为绝对路径。
   - `name(path)`: 获取路径的最后一部分（文件名或目录名）。
   - `parent(path)`: 获取路径的父目录。
   - `relative_to(path1, path2)`: 计算 `path1` 相对于 `path2` 的相对路径。
   - `replace_suffix(path, suffix)`: 替换路径的文件后缀。
   - `stem(path)`: 获取路径的文件名部分，不包含后缀。

2. **文件属性检查:**
   - `exists(path)`: 判断路径是否存在。
   - `is_dir(path)`: 判断路径是否为目录。
   - `is_file(path)`: 判断路径是否为文件。
   - `is_samepath(path1, path2)`: 判断两个路径是否指向同一个文件或目录。
   - `is_symlink(path)`: 判断路径是否为符号链接。
   - `size(path)`: 获取文件的大小。

3. **文件内容操作:**
   - `read(path, encoding='utf-8')`: 读取文件内容，并按指定的编码解码为字符串。
   - `hash(path, algorithm)`: 计算文件的哈希值。

4. **文件操作:**
   - `copyfile(source, destination=None, install=False, install_dir=None, install_mode=None, install_tag=None)`: 将文件复制到构建目录，可以选择是否安装到指定目录。

**与逆向方法的关系及举例说明：**

该模块本身是构建系统的一部分，直接服务于 Frida 的开发过程，但其提供的功能在逆向工程中也有应用场景：

* **读取目标程序信息:**  在 Frida 的构建过程中，可能需要读取目标程序（或相关库）的元数据信息，例如版本号、配置信息等。 `fs.read()` 函数可以用来读取这些文件。
    * **举例：** 假设 Frida 需要读取目标 Android 应用的 `AndroidManifest.xml` 文件来获取包名和版本信息。构建脚本可以使用 `fs.read('path/to/AndroidManifest.xml')` 来读取文件内容，然后解析 XML 数据。

* **验证文件完整性:** 在分发或安装 Frida 组件时，可以使用 `fs.hash()` 函数计算文件的哈希值，与预期的哈希值进行比较，以验证文件的完整性，防止篡改。
    * **举例：**  在 Frida 的发布流程中，可以计算 Frida Agent 的二进制文件的 SHA256 哈希值，并将其记录在发布文件中。用户下载后，可以使用相同的 `fs.hash()` 函数验证下载的 Agent 文件是否与官方发布的一致。

* **处理目标程序文件路径:**  逆向工程师经常需要处理目标程序的文件路径，例如查找配置文件、库文件等。`fs` 模块的路径处理功能可以简化这些操作。
    * **举例：**  Frida 脚本可能需要根据目标进程的安装路径，动态构造其配置文件的完整路径。可以使用 `fs.parent()` 获取安装目录，然后拼接配置文件名。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明：**

虽然该模块本身是高级的 Python 代码，但其操作最终会涉及到操作系统底层的概念：

* **文件系统抽象:**  该模块提供的功能是对底层文件系统调用的抽象，例如 `open()`, `read()`, `stat()`, `mkdir()`, `copy()` 等系统调用。在 Linux 和 Android 上，这些调用会与内核的文件系统层交互。
* **文件路径:**  路径的概念是操作系统中组织文件的核心。绝对路径和相对路径、符号链接等都是操作系统内核管理的。`fs` 模块处理这些路径，最终会转化为内核可以理解的形式。
* **文件属性:**  `fs.size()`, `fs.is_file()`, `fs.is_dir()` 等功能依赖于获取文件的元数据，这些元数据由操作系统内核维护，例如 inode 中的信息。
* **文件权限:**  虽然该模块没有直接操作文件权限的功能，但 `copyfile` 函数的 `install_mode` 参数允许设置安装后文件的权限，这直接关联到 Linux/Android 的用户权限模型。
* **Android 特性:**  在 Frida 对 Android 进行 instrumentation 时，可能会涉及到访问 Android 特有的文件路径，例如 `/data/data/<package_name>/` 或 `/system/lib/` 等。`fs` 模块可以用来操作这些路径。

**逻辑推理，假设输入与输出：**

* **假设输入:** `fs.is_file('my_script.py')`，当前构建目录存在名为 `my_script.py` 的文件。
* **输出:** `True`

* **假设输入:** `fs.size('/tmp/large_file.bin')`，`/tmp/large_file.bin` 是一个大小为 1048576 字节的文件。
* **输出:** `1048576`

* **假设输入:** `fs.relative_to('/path/to/file.txt', '/path/')`
* **输出:** `'to/file.txt'`

* **假设输入:** `fs.copyfile('input.txt', 'output.txt')`，当前构建目录存在 `input.txt`。
* **输出:**  会在构建目录中生成一个名为 `output.txt` 的文件，内容与 `input.txt` 相同。

**涉及用户或者编程常见的使用错误及举例说明：**

* **路径不存在:** 调用 `fs.read()` 或 `fs.size()` 等函数时，如果提供的路径指向的文件不存在，会导致 `MesonException`。
    * **举例：** `fs.read('non_existent_file.txt')` 会抛出异常。

* **尝试哈希目录:** `fs.hash()` 函数只能用于文件，如果尝试哈希一个目录，会抛出 `MesonException`。
    * **举例：** `fs.hash('/tmp', 'sha256')` 会抛出异常，提示 `/tmp` 不是一个文件。

* **`copyfile` 未指定 `install_dir` 但 `install=True`:** 如果在调用 `fs.copyfile()` 时设置了 `install=True`，但没有提供 `install_dir` 参数，会导致 `InvalidArguments` 异常。
    * **举例：** `fs.copyfile('my_file.txt', install=True)` 会抛出异常。

* **`fs.read` 读取构建目录内的文件:** 为了防止构建循环，`fs.read()` 明确禁止读取构建目录内的文件。
    * **举例：** 假设构建目录为 `builddir`，执行 `fs.read('builddir/generated_file.txt')` 会抛出异常。

* **`copyfile` 的目标路径包含路径分隔符:**  `copyfile` 的目标路径（第二个位置参数）不允许包含路径分隔符，这意味着只能在当前构建目录下创建文件，不能指定子目录。
    * **举例：** `fs.copyfile('input.txt', 'subdir/output.txt')` 会抛出 `InvalidArguments` 异常。

**说明用户操作是如何一步步的到达这里，作为调试线索。**

用户通常不会直接编辑或运行 `fs.py` 这个文件。这个文件是 Meson 构建系统的一部分，在 Frida 的构建过程中被 Meson 自动加载和使用。用户与这个文件的交互是间接的，通过编写 Frida 的 `meson.build` 构建脚本来实现。

以下是一个用户操作到达 `fs.py` 的情景：

1. **用户修改 Frida 项目的 `meson.build` 文件。**  这是用户与构建系统交互的主要方式。例如，用户可能需要在构建过程中复制一个额外的文件到构建目录。

2. **用户在 `meson.build` 文件中调用了 `fs` 模块提供的函数。**  例如，用户可能会添加如下代码：
   ```python
   fs = import('fs')
   fs.copyfile('my_config.ini', install=true, install_dir='share/frida')
   ```
   这行代码指示 Meson 在构建时将 `my_config.ini` 文件复制到 `share/frida` 目录下（如果启用了安装）。

3. **用户运行 Meson 构建命令。**  例如，在 Frida 项目的根目录下执行 `meson setup builddir` 和 `ninja -C builddir`。

4. **Meson 解析 `meson.build` 文件。** 当 Meson 执行到包含 `fs.copyfile()` 的代码时，它会加载 `frida/subprojects/frida-clr/releng/meson/mesonbuild/modules/fs.py` 文件，并调用 `copyfile` 方法。

5. **`fs.py` 中的代码被执行。** `copyfile` 方法会创建相应的构建步骤，指示构建系统在构建时执行文件复制操作。

**作为调试线索：**

* **构建错误信息:** 如果 `meson.build` 中使用了错误的 `fs` 函数参数，例如上面提到的用户错误，Meson 会在解析 `meson.build` 时或在构建过程中报错，错误信息可能会指向调用的 `fs` 函数和相关的参数。
* **查看 `build.ninja` 文件:** Meson 会根据 `meson.build` 的描述生成 `build.ninja` 文件，其中包含了实际的构建命令。可以查看 `build.ninja` 文件，了解 `fs.copyfile` 等操作是如何转化为具体的构建步骤的。
* **Meson 的调试输出:** Meson 提供了调试选项，可以输出更详细的构建过程信息，有助于理解 `fs` 模块的执行情况。
* **断点调试 Meson 源码:**  对于 Frida 的开发者，如果需要深入了解 `fs` 模块的执行逻辑，可以在 Meson 的源码中设置断点进行调试。

总而言之，`fs.py` 模块是 Frida 构建流程中处理文件系统操作的关键组件。理解其功能和使用方式，对于理解 Frida 的构建过程和解决构建问题至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/modules/fs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2019 The Meson development team

from __future__ import annotations
from pathlib import Path, PurePath, PureWindowsPath
import hashlib
import os
import typing as T

from . import ExtensionModule, ModuleReturnValue, ModuleInfo
from .. import mlog
from ..build import BuildTarget, CustomTarget, CustomTargetIndex, InvalidArguments
from ..interpreter.type_checking import INSTALL_KW, INSTALL_MODE_KW, INSTALL_TAG_KW, NoneType
from ..interpreterbase import FeatureNew, KwargInfo, typed_kwargs, typed_pos_args, noKwargs
from ..mesonlib import File, MesonException, has_path_sep, path_is_in_root, relpath

if T.TYPE_CHECKING:
    from . import ModuleState
    from ..build import BuildTargetTypes
    from ..interpreter import Interpreter
    from ..interpreterbase import TYPE_kwargs
    from ..mesonlib import FileOrString, FileMode

    from typing_extensions import TypedDict

    class ReadKwArgs(TypedDict):
        """Keyword Arguments for fs.read."""

        encoding: str

    class CopyKw(TypedDict):

        """Kwargs for fs.copy"""

        install: bool
        install_dir: T.Optional[str]
        install_mode: FileMode
        install_tag: T.Optional[str]


class FSModule(ExtensionModule):

    INFO = ModuleInfo('fs', '0.53.0')

    def __init__(self, interpreter: 'Interpreter') -> None:
        super().__init__(interpreter)
        self.methods.update({
            'as_posix': self.as_posix,
            'copyfile': self.copyfile,
            'exists': self.exists,
            'expanduser': self.expanduser,
            'hash': self.hash,
            'is_absolute': self.is_absolute,
            'is_dir': self.is_dir,
            'is_file': self.is_file,
            'is_samepath': self.is_samepath,
            'is_symlink': self.is_symlink,
            'name': self.name,
            'parent': self.parent,
            'read': self.read,
            'relative_to': self.relative_to,
            'replace_suffix': self.replace_suffix,
            'size': self.size,
            'stem': self.stem,
        })

    def _absolute_dir(self, state: 'ModuleState', arg: 'FileOrString') -> Path:
        """
        make an absolute path from a relative path, WITHOUT resolving symlinks
        """
        if isinstance(arg, File):
            return Path(arg.absolute_path(state.source_root, state.environment.get_build_dir()))
        return Path(state.source_root) / Path(state.subdir) / Path(arg).expanduser()

    @staticmethod
    def _obj_to_path(feature_new_prefix: str, obj: T.Union[FileOrString, BuildTargetTypes], state: ModuleState) -> PurePath:
        if isinstance(obj, str):
            return PurePath(obj)

        if isinstance(obj, File):
            FeatureNew(f'{feature_new_prefix} with file', '0.59.0').use(state.subproject, location=state.current_node)
            return PurePath(str(obj))

        FeatureNew(f'{feature_new_prefix} with build_tgt, custom_tgt, and custom_idx', '1.4.0').use(state.subproject, location=state.current_node)
        return PurePath(state.backend.get_target_filename(obj))

    def _resolve_dir(self, state: 'ModuleState', arg: 'FileOrString') -> Path:
        """
        resolves symlinks and makes absolute a directory relative to calling meson.build,
        if not already absolute
        """
        path = self._absolute_dir(state, arg)
        try:
            # accommodate unresolvable paths e.g. symlink loops
            path = path.resolve()
        except Exception:
            # return the best we could do
            pass
        return path

    @noKwargs
    @FeatureNew('fs.expanduser', '0.54.0')
    @typed_pos_args('fs.expanduser', str)
    def expanduser(self, state: 'ModuleState', args: T.Tuple[str], kwargs: T.Dict[str, T.Any]) -> str:
        return str(Path(args[0]).expanduser())

    @noKwargs
    @FeatureNew('fs.is_absolute', '0.54.0')
    @typed_pos_args('fs.is_absolute', (str, File))
    def is_absolute(self, state: 'ModuleState', args: T.Tuple['FileOrString'], kwargs: T.Dict[str, T.Any]) -> bool:
        if isinstance(args[0], File):
            FeatureNew('fs.is_absolute with file', '0.59.0').use(state.subproject, location=state.current_node)
        return PurePath(str(args[0])).is_absolute()

    @noKwargs
    @FeatureNew('fs.as_posix', '0.54.0')
    @typed_pos_args('fs.as_posix', str)
    def as_posix(self, state: 'ModuleState', args: T.Tuple[str], kwargs: T.Dict[str, T.Any]) -> str:
        r"""
        this function assumes you are passing a Windows path, even if on a Unix-like system
        and so ALL '\' are turned to '/', even if you meant to escape a character
        """
        return PureWindowsPath(args[0]).as_posix()

    @noKwargs
    @typed_pos_args('fs.exists', str)
    def exists(self, state: 'ModuleState', args: T.Tuple[str], kwargs: T.Dict[str, T.Any]) -> bool:
        return self._resolve_dir(state, args[0]).exists()

    @noKwargs
    @typed_pos_args('fs.is_symlink', (str, File))
    def is_symlink(self, state: 'ModuleState', args: T.Tuple['FileOrString'], kwargs: T.Dict[str, T.Any]) -> bool:
        if isinstance(args[0], File):
            FeatureNew('fs.is_symlink with file', '0.59.0').use(state.subproject, location=state.current_node)
        return self._absolute_dir(state, args[0]).is_symlink()

    @noKwargs
    @typed_pos_args('fs.is_file', str)
    def is_file(self, state: 'ModuleState', args: T.Tuple[str], kwargs: T.Dict[str, T.Any]) -> bool:
        return self._resolve_dir(state, args[0]).is_file()

    @noKwargs
    @typed_pos_args('fs.is_dir', str)
    def is_dir(self, state: 'ModuleState', args: T.Tuple[str], kwargs: T.Dict[str, T.Any]) -> bool:
        return self._resolve_dir(state, args[0]).is_dir()

    @noKwargs
    @typed_pos_args('fs.hash', (str, File), str)
    def hash(self, state: 'ModuleState', args: T.Tuple['FileOrString', str], kwargs: T.Dict[str, T.Any]) -> str:
        if isinstance(args[0], File):
            FeatureNew('fs.hash with file', '0.59.0').use(state.subproject, location=state.current_node)
        file = self._resolve_dir(state, args[0])
        if not file.is_file():
            raise MesonException(f'{file} is not a file and therefore cannot be hashed')
        try:
            h = hashlib.new(args[1])
        except ValueError:
            raise MesonException('hash algorithm {} is not available'.format(args[1]))
        mlog.debug('computing {} sum of {} size {} bytes'.format(args[1], file, file.stat().st_size))
        h.update(file.read_bytes())
        return h.hexdigest()

    @noKwargs
    @typed_pos_args('fs.size', (str, File))
    def size(self, state: 'ModuleState', args: T.Tuple['FileOrString'], kwargs: T.Dict[str, T.Any]) -> int:
        if isinstance(args[0], File):
            FeatureNew('fs.size with file', '0.59.0').use(state.subproject, location=state.current_node)
        file = self._resolve_dir(state, args[0])
        if not file.is_file():
            raise MesonException(f'{file} is not a file and therefore cannot be sized')
        try:
            return file.stat().st_size
        except ValueError:
            raise MesonException('{} size could not be determined'.format(args[0]))

    @noKwargs
    @typed_pos_args('fs.is_samepath', (str, File), (str, File))
    def is_samepath(self, state: 'ModuleState', args: T.Tuple['FileOrString', 'FileOrString'], kwargs: T.Dict[str, T.Any]) -> bool:
        if isinstance(args[0], File) or isinstance(args[1], File):
            FeatureNew('fs.is_samepath with file', '0.59.0').use(state.subproject, location=state.current_node)
        file1 = self._resolve_dir(state, args[0])
        file2 = self._resolve_dir(state, args[1])
        if not file1.exists():
            return False
        if not file2.exists():
            return False
        try:
            return file1.samefile(file2)
        except OSError:
            return False

    @noKwargs
    @typed_pos_args('fs.replace_suffix', (str, File, CustomTarget, CustomTargetIndex, BuildTarget), str)
    def replace_suffix(self, state: 'ModuleState', args: T.Tuple[T.Union[FileOrString, BuildTargetTypes], str], kwargs: T.Dict[str, T.Any]) -> str:
        path = self._obj_to_path('fs.replace_suffix', args[0], state)
        return str(path.with_suffix(args[1]))

    @noKwargs
    @typed_pos_args('fs.parent', (str, File, CustomTarget, CustomTargetIndex, BuildTarget))
    def parent(self, state: 'ModuleState', args: T.Tuple[T.Union[FileOrString, BuildTargetTypes]], kwargs: T.Dict[str, T.Any]) -> str:
        path = self._obj_to_path('fs.parent', args[0], state)
        return str(path.parent)

    @noKwargs
    @typed_pos_args('fs.name', (str, File, CustomTarget, CustomTargetIndex, BuildTarget))
    def name(self, state: 'ModuleState', args: T.Tuple[T.Union[FileOrString, BuildTargetTypes]], kwargs: T.Dict[str, T.Any]) -> str:
        path = self._obj_to_path('fs.name', args[0], state)
        return str(path.name)

    @noKwargs
    @typed_pos_args('fs.stem', (str, File, CustomTarget, CustomTargetIndex, BuildTarget))
    @FeatureNew('fs.stem', '0.54.0')
    def stem(self, state: 'ModuleState', args: T.Tuple[T.Union[FileOrString, BuildTargetTypes]], kwargs: T.Dict[str, T.Any]) -> str:
        path = self._obj_to_path('fs.stem', args[0], state)
        return str(path.stem)

    @FeatureNew('fs.read', '0.57.0')
    @typed_pos_args('fs.read', (str, File))
    @typed_kwargs('fs.read', KwargInfo('encoding', str, default='utf-8'))
    def read(self, state: 'ModuleState', args: T.Tuple['FileOrString'], kwargs: 'ReadKwArgs') -> str:
        """Read a file from the source tree and return its value as a decoded
        string.

        If the encoding is not specified, the file is assumed to be utf-8
        encoded. Paths must be relative by default (to prevent accidents) and
        are forbidden to be read from the build directory (to prevent build
        loops)
        """
        path = args[0]
        encoding = kwargs['encoding']
        src_dir = state.environment.source_dir
        sub_dir = state.subdir
        build_dir = state.environment.get_build_dir()

        if isinstance(path, File):
            if path.is_built:
                raise MesonException(
                    'fs.read does not accept built files() objects')
            path = os.path.join(src_dir, path.relative_name())
        else:
            if sub_dir:
                src_dir = os.path.join(src_dir, sub_dir)
            path = os.path.join(src_dir, path)

        path = os.path.abspath(path)
        if path_is_in_root(Path(path), Path(build_dir), resolve=True):
            raise MesonException('path must not be in the build tree')
        try:
            with open(path, encoding=encoding) as f:
                data = f.read()
        except FileNotFoundError:
            raise MesonException(f'File {args[0]} does not exist.')
        except UnicodeDecodeError:
            raise MesonException(f'decoding failed for {args[0]}')
        # Reconfigure when this file changes as it can contain data used by any
        # part of the build configuration (e.g. `project(..., version:
        # fs.read_file('VERSION')` or `configure_file(...)`
        self.interpreter.add_build_def_file(path)
        return data

    @FeatureNew('fs.copyfile', '0.64.0')
    @typed_pos_args('fs.copyfile', (File, str), optargs=[str])
    @typed_kwargs(
        'fs.copyfile',
        INSTALL_KW,
        INSTALL_MODE_KW,
        INSTALL_TAG_KW,
        KwargInfo('install_dir', (str, NoneType)),
    )
    def copyfile(self, state: ModuleState, args: T.Tuple[FileOrString, T.Optional[str]],
                 kwargs: CopyKw) -> ModuleReturnValue:
        """Copy a file into the build directory at build time."""
        if kwargs['install'] and not kwargs['install_dir']:
            raise InvalidArguments('"install_dir" must be specified when "install" is true')

        src = self.interpreter.source_strings_to_files([args[0]])[0]

        # The input is allowed to have path separators, but the output may not,
        # so use the basename for the default case
        dest = args[1] if args[1] else os.path.basename(src.fname)
        if has_path_sep(dest):
            raise InvalidArguments('Destination path may not have path separators')

        ct = CustomTarget(
            dest,
            state.subdir,
            state.subproject,
            state.environment,
            state.environment.get_build_command() + ['--internal', 'copy', '@INPUT@', '@OUTPUT@'],
            [src],
            [dest],
            state.is_build_only_subproject,
            build_by_default=True,
            install=kwargs['install'],
            install_dir=[kwargs['install_dir']],
            install_mode=kwargs['install_mode'],
            install_tag=[kwargs['install_tag']],
            backend=state.backend,
            description='Copying file {}',
        )

        return ModuleReturnValue(ct, [ct])

    @FeatureNew('fs.relative_to', '1.3.0')
    @typed_pos_args('fs.relative_to', (str, File, CustomTarget, CustomTargetIndex, BuildTarget), (str, File, CustomTarget, CustomTargetIndex, BuildTarget))
    @noKwargs
    def relative_to(self, state: ModuleState, args: T.Tuple[T.Union[FileOrString, BuildTargetTypes], T.Union[FileOrString, BuildTargetTypes]], kwargs: TYPE_kwargs) -> str:
        def to_path(arg: T.Union[FileOrString, CustomTarget, CustomTargetIndex, BuildTarget]) -> str:
            if isinstance(arg, File):
                return arg.absolute_path(state.environment.source_dir, state.environment.build_dir)
            elif isinstance(arg, (CustomTarget, CustomTargetIndex, BuildTarget)):
                return state.backend.get_target_filename_abs(arg)
            else:
                return os.path.join(state.environment.source_dir, state.subdir, arg)

        t = to_path(args[0])
        f = to_path(args[1])

        return relpath(t, f)


def initialize(*args: T.Any, **kwargs: T.Any) -> FSModule:
    return FSModule(*args, **kwargs)
```