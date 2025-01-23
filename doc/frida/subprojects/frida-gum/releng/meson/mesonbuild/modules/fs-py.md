Response:
Let's break down the thought process for analyzing this Python code.

**1. Understanding the Goal:**

The primary request is to understand the functionality of the `fs.py` file within the Frida dynamic instrumentation tool. Specifically, it asks about its relation to reverse engineering, low-level concepts, logical reasoning, potential errors, and how a user might interact with it.

**2. Initial Code Scan and Keyword Recognition:**

The first step is a quick scan of the code, looking for recognizable keywords and patterns. This helps to get a high-level overview. Keywords like `def`, `class`, `import`, and specific method names like `copyfile`, `read`, `hash`, `exists`, etc., stand out. The docstrings also provide valuable clues. The import of `hashlib`, `os`, `pathlib`, and elements from the Meson build system (`BuildTarget`, `CustomTarget`, etc.) are important hints about the module's purpose.

**3. Identifying Core Functionality (Method by Method):**

The code defines a class `FSModule` with several methods. The most effective approach is to analyze each method individually:

* **`__init__`:**  Standard initialization, noting it registers methods.
* **`_absolute_dir` and `_resolve_dir`:** These immediately suggest path manipulation, which is crucial for file system operations. The distinction between absolute and resolved paths is also important.
* **`_obj_to_path`:**  This function handles different input types (strings, `File` objects, build targets), converting them to paths. This is key for the module's flexibility.
* **`expanduser`:**  Basic path manipulation.
* **`is_absolute`, `as_posix`:**  More path manipulation, specifically dealing with absolute paths and Windows-style paths.
* **`exists`, `is_symlink`, `is_file`, `is_dir`:** Standard file system checks. Their relevance to reverse engineering becomes clear when you consider inspecting the target application's file system.
* **`hash`:**  This directly relates to data integrity and can be used in reverse engineering to identify files or verify modifications.
* **`size`:**  Simple but useful for file analysis.
* **`is_samepath`:** Comparing file paths, potentially important for tracking files during reverse engineering.
* **`replace_suffix`, `parent`, `name`, `stem`:**  More path manipulation, useful for dissecting file paths.
* **`read`:**  Reading file contents. This is *highly* relevant for reverse engineering as it allows inspection of configuration files, scripts, and even potentially parts of the application's code. The security checks (no reading from build directory) are also important to note.
* **`copyfile`:** Copying files, useful for setting up testing environments or extracting files from the target. The connection to the Meson build system is evident here.
* **`relative_to`:** Calculating relative paths.

**4. Connecting Functionality to Reverse Engineering:**

As each method is analyzed, consider how it could be used in a reverse engineering context. For example:

* Checking if a specific library exists (`exists`).
* Verifying the integrity of an executable using its hash (`hash`).
* Examining configuration files used by the target application (`read`).
* Identifying the parent directory of a loaded module (`parent`).
* Copying a suspicious file for offline analysis (`copyfile`).
* Understanding the structure of the application's file system.

**5. Identifying Low-Level, Kernel, and Framework Connections:**

The use of `os` and `pathlib` directly links to operating system interactions. The mention of Linux and Android kernel/framework is a bit more indirect. While this module *itself* doesn't directly interact with the kernel, Frida, as a whole, certainly does. This `fs` module provides utilities that *facilitate* interaction with the file system *of the target process*, which could be running on Linux or Android. Think of it as a higher-level abstraction over low-level file system calls.

**6. Logical Reasoning and Examples:**

For each method, imagine specific input and what the expected output would be. This helps solidify understanding and identify potential edge cases. For example, with `is_file`, if given a path to a directory, the output should be `False`.

**7. Identifying User Errors:**

Consider common mistakes a user might make when using these functions. Examples include:

* Providing an incorrect path.
* Trying to hash a directory instead of a file.
* Trying to read a binary file without specifying the correct encoding.
* Making mistakes with relative vs. absolute paths.
* Not understanding the restrictions on reading files in the build directory.

**8. Tracing User Interaction (Debugging Clues):**

Think about how a user in the Frida ecosystem would end up using this `fs` module. The most likely scenario is within a Frida script or as part of a larger Frida-based tool. The user would be interacting with the Frida API, which in turn would use this `fs` module to perform file system operations on the target process or the host system (where the Frida script is running). The `meson.build` path in the initial description indicates this module is part of Frida's build system, meaning it's used during the *development* of Frida itself, and its functionalities are exposed for use in Frida scripts.

**9. Structuring the Answer:**

Finally, organize the information logically, grouping similar points together. Use clear headings and examples to make the explanation easy to understand. Address each part of the original request (functionality, reverse engineering, low-level concepts, etc.) explicitly.

**Self-Correction/Refinement during the process:**

* **Initial thought:** This module directly interacts with the Android kernel.
* **Correction:**  While Frida *can* interact with the kernel, this specific module provides higher-level file system utilities. It's used *by* Frida to interact with the target's file system, which might be on Android.

* **Initial thought:**  Just list the functions.
* **Refinement:**  Explain *what* each function does and *why* it's relevant, especially to reverse engineering. Provide examples.

* **Initial thought:** Focus only on the code.
* **Refinement:**  Consider the broader context of Frida and how a user would interact with this module.

By following these steps and iteratively refining the understanding, a comprehensive and accurate analysis of the `fs.py` module can be achieved.
This Python file, `fs.py`, is a module within the Frida dynamic instrumentation tool's build system (Meson). It provides a set of functions for interacting with the file system during the build process. Think of it as a way for the build scripts to perform file-related tasks.

Here's a breakdown of its functionalities:

**Core File System Operations:**

* **`exists(path)`:** Checks if a given path (file or directory) exists.
* **`is_symlink(path)`:** Checks if a given path is a symbolic link.
* **`is_file(path)`:** Checks if a given path is a regular file.
* **`is_dir(path)`:** Checks if a given path is a directory.
* **`hash(path, algorithm)`:** Calculates the hash (e.g., SHA256, MD5) of a file's content.
* **`size(path)`:** Returns the size of a file in bytes.
* **`is_samepath(path1, path2)`:** Checks if two paths refer to the same file or directory.
* **`read(path, encoding='utf-8')`:** Reads the content of a text file, with optional encoding specification. It prevents reading from the build directory to avoid build loops.
* **`copyfile(source, destination=None, install=False, install_dir=None, install_mode=None, install_tag=None)`:** Copies a file. It can also handle installing the copied file to a specific directory with specified permissions and tags.

**Path Manipulation:**

* **`expanduser(path)`:** Expands the `~` symbol in a path to the user's home directory.
* **`is_absolute(path)`:** Checks if a path is absolute.
* **`as_posix(path)`:** Converts a Windows path to its POSIX equivalent (using forward slashes).
* **`replace_suffix(path, suffix)`:** Replaces the suffix (file extension) of a path.
* **`parent(path)`:** Returns the parent directory of a path.
* **`name(path)`:** Returns the final component of a path (filename with extension).
* **`stem(path)`:** Returns the filename without the extension.
* **`relative_to(path1, path2)`:**  Calculates the relative path from `path2` to `path1`.

**Relationship to Reverse Engineering:**

While this module operates within the *build process* of Frida, its functionalities can indirectly relate to reverse engineering in the following ways:

* **Verification and Integrity:** The `hash` function can be used during the build to ensure the integrity of files that are part of Frida or its components. In reverse engineering, verifying the hash of a binary can confirm if it has been tampered with.
    * **Example:** During the Frida build, a script might calculate the SHA256 hash of the `frida-server` binary and store it. This hash can later be used by developers or advanced users to verify the authenticity of the distributed binary.
* **Configuration and Data Extraction:** The `read` function allows build scripts to read configuration files or data files. In reverse engineering, examining configuration files or data embedded within binaries is a common practice.
    * **Example:** A Frida build script might read a file containing default values for certain settings. A reverse engineer examining Frida's source code or build scripts could find this and understand how Frida is configured by default.
* **File System Structure Understanding:** The path manipulation functions (`parent`, `name`, `stem`, `relative_to`) help organize and manage files within the build system. Understanding the file system structure of a target application is crucial in reverse engineering to locate specific components. While this module operates on the *build* structure, the concepts are similar.
* **Packaging and Distribution:** The `copyfile` function with installation options helps in packaging Frida's components for distribution. Understanding how software is packaged and installed can be relevant in reverse engineering when analyzing how an application is deployed.

**Binary 底层, Linux, Android 内核及框架的知识:**

This module itself doesn't directly interact with the binary level, Linux/Android kernel, or frameworks *at runtime*. It operates during the *build process*. However, it uses standard Python libraries (`os`, `pathlib`, `hashlib`) that ultimately rely on underlying operating system functionalities.

* **`os` and `pathlib`:** These libraries provide platform-independent ways to interact with the file system. On Linux and Android, these calls will eventually translate to system calls that the kernel handles. For example, `os.path.exists()` on Linux will likely call the `stat()` system call.
* **`hashlib`:** This library provides implementations of various cryptographic hash functions. These algorithms are fundamental in computer science and are used extensively in various parts of the operating system and software.
* **Installation:** The `install` functionality utilizes Meson's build system, which will ultimately use tools like `install` (on Linux) to copy files to their destination directories and set permissions. This involves understanding file system permissions and ownership, concepts central to Linux and Android security.

**逻辑推理:**

Let's take the `read` function as an example of logical reasoning:

* **Assumption:**  Build scripts need to read data from source files.
* **Input:** A relative or absolute path to a file within the source tree.
* **Logic:**
    1. Construct the absolute path to the file.
    2. **Crucial Check:** Verify that the path is NOT within the build directory. This prevents a build loop where a script reads a file generated by the build, which then triggers another build, and so on.
    3. Open the file with the specified encoding (defaulting to UTF-8).
    4. Read the file's content.
    5. Register the file as a "build definition file". This tells Meson to re-run the build if this file changes.
* **Output:** The content of the file as a string.

**假设输入与输出 (for `read`):**

* **假设输入:** `path = 'data/version.txt'`, `encoding = 'utf-8'`
* **文件 'data/version.txt' 的内容:** `1.2.3`
* **输出:** `'1.2.3'`

**用户或编程常见的使用错误:**

* **Incorrect Path:** Providing a path that doesn't exist will raise a `FileNotFoundError`.
    * **Example:** `fs.read('nonexistent_file.txt')`
* **Incorrect Encoding:** Trying to read a file with the wrong encoding can lead to `UnicodeDecodeError`.
    * **Example:** Trying to read a UTF-16 encoded file with the default UTF-8 encoding: `fs.read('utf16_file.txt')`
* **Reading from Build Directory:** Attempting to read a file inside the build directory will raise a `MesonException`.
    * **Example:** Assuming `output.txt` is generated in the build directory, `fs.read('../build/output.txt')` will fail.
* **Trying to Hash a Directory:** The `hash` function expects a file. Providing a directory path will raise a `MesonException`.
    * **Example:** `fs.hash('src_directory', 'sha256')`

**用户操作是如何一步步的到达这里，作为调试线索:**

This `fs.py` module is not directly invoked by a user running Frida for dynamic instrumentation. Instead, it's used by the *developers* of Frida during the build process. Here's a likely scenario:

1. **Frida Developer Modifies Build Scripts:** A developer working on Frida might need to perform some file system operation as part of the build process (e.g., copying a resource file, reading a version number).
2. **Developer Uses `fs` Module in `meson.build`:**  They would use the functions provided by this `fs.py` module within their `meson.build` files. For example:
   ```meson
   # meson.build
   version_file = fs.read('VERSION')
   configure_file(
       input: 'config.h.in',
       output: 'config.h',
       configuration: {'VERSION': version_file}
   )
   ```
3. **Meson Executes Build Scripts:** When the developer runs the Meson build command (e.g., `meson setup builddir`, `ninja -C builddir`), Meson will parse and execute the `meson.build` files.
4. **`fs.py` Functions are Called:**  During the execution of the build scripts, the functions defined in `fs.py` are called to perform the requested file system operations.
5. **Potential Errors and Debugging:** If there's an issue (e.g., incorrect path in `fs.read`), Meson will report an error originating from the `fs.py` module. The developer would then:
   * **Examine the `meson.build` file:** Check how the `fs` module functions are being used and with what arguments.
   * **Verify file paths:** Ensure the paths provided to the `fs` functions are correct relative to the source directory.
   * **Check file permissions:** Make sure the build process has the necessary permissions to read or write the files.
   * **Review Meson's output:** Meson provides detailed logs that can help pinpoint the source of the error.

In summary, while end-users of Frida don't directly interact with `fs.py`, it's a crucial utility for Frida's developers to manage files and perform file-related tasks during the build process, and errors in its usage would manifest as build failures.

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/fs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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