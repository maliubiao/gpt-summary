Response:
Let's break down the thought process for analyzing the `wrap.py` code.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of this Python file, specifically within the context of the Frida dynamic instrumentation tool (though the provided code is from Meson, a build system, which Frida uses for its build process). The request also asks for connections to reverse engineering, low-level details, logical reasoning, common user errors, and how a user might reach this code.

**2. Initial Skim and Keyword Spotting:**

I'd start by quickly skimming the code, looking for familiar keywords and patterns. Things that immediately jump out:

* **`# SPDX-License-Identifier: Apache-2.0` and `Copyright`:** Standard licensing and copyright information, indicating an open-source project.
* **`from __future__ import annotations`:**  Modern Python syntax for type hinting.
* **`import ...`:**  A lot of standard library imports: `os`, `shutil`, `urllib`, `hashlib`, `tempfile`, `subprocess`, `configparser`, `json`, etc. This suggests the code deals with file manipulation, network operations, configuration parsing, and external process execution.
* **`from .. ...`:** Imports from within the Meson project structure, indicating dependencies on other Meson modules.
* **`dataclass`:** Used for creating simple classes with automatically generated methods, making `Resolver` a key data structure.
* **`lru_cache`:**  A decorator for memoization, suggesting optimization for repeated function calls.
* **`WrapMode`, `MesonException`, `FeatureNew`, `SubProject`:** These are specific to Meson's vocabulary and hints at the purpose of this module within Meson.
* **`whitelist_wrapdb`, `open_wrapdburl`, `get_releases`:** These function names clearly indicate interaction with a remote service called "WrapDB."
* **`PackageDefinition`:** A class likely representing the metadata and source information for an external package.
* **`Resolver`:**  A class that seems to be responsible for finding and managing external dependencies.
* **`resolve`, `_get_file`, `_get_git`, `_get_hg`, `_get_svn`:** These method names within `Resolver` strongly suggest handling different ways of obtaining external package source code.
* **`.wrap` file extension:**  This is a key indicator of Meson's wrap system for managing dependencies.

**3. Formulating a High-Level Understanding:**

Based on the keywords, I'd form a preliminary hypothesis:  This `wrap.py` file is part of Meson's subproject dependency management system. It seems to handle downloading, patching, and integrating external libraries into a Meson build. The "WrapDB" likely acts as a repository for these dependency definitions.

**4. Deeper Dive and Functional Analysis:**

Now, I'd go through the code section by section, focusing on the purpose of each class and function:

* **`whitelist_wrapdb`, `open_wrapdburl`, `get_releases`, `update_wrap_file`, `parse_patch_url`:** These functions clearly deal with fetching data from WrapDB, validating URLs, and handling potential security concerns (SSL, whitelisting).
* **`WrapException`, `WrapNotFoundException`:** Custom exceptions for specific error conditions in the wrap system.
* **`PackageDefinition`:** This class parses `.wrap` files, extracting information about the dependency's source (URL, type, revision, patches), provided dependencies and programs, and directory structure. The `parse_wrap` and `parse_provide_section` methods are crucial for understanding the structure of `.wrap` files. The `redirect` functionality is also important.
* **`Resolver`:**  This is the core component. It manages a collection of `PackageDefinition` objects. Key methods include:
    * `load_wraps`:  Locates and parses `.wrap` files in the subprojects directory.
    * `load_wrapdb`: Loads a local `wrapdb.json` file (likely for caching or offline use).
    * `get_from_wrapdb`: Downloads `.wrap` files from the online WrapDB.
    * `find_dep_provider`, `find_program_provider`:  Locates which wrap file provides a given dependency or program.
    * `resolve`: The central function for resolving a dependency. It determines the source location (local or remote), downloads or checks out the source, and applies patches. The different `_get_...` methods handle specific source types (file, git, hg, svn).
    * `apply_patch`, `apply_diff_files`:  Apply patches to the downloaded source code.
    * `validate`: Checks if the local `.wrap` file has been modified since the last configuration.

**5. Connecting to the Prompt's Specific Questions:**

* **Reverse Engineering:** The patching mechanism (`apply_patch`, `apply_diff_files`) is directly related to reverse engineering workflows where modifications are applied to existing code. Downloading source code can also be a step in reverse engineering.
* **Binary/Low-Level/Kernel:** While this specific code doesn't directly interact with binaries or the kernel, it *facilitates* the building of software that *does*. The downloading and patching steps prepare the source code for compilation. The mention of Android could relate to how Frida itself is built, but this code is more about the build system's dependency management.
* **Logical Reasoning:** The `resolve` method involves decision-making based on the presence of local files, the content of `.wrap` files, and the availability of network resources. The branching logic within `resolve` and the different `_get_...` methods illustrate this.
* **User Errors:** Missing dependencies, incorrect `.wrap` file syntax, network issues, and conflicts between different wrap files providing the same dependency are potential user errors.
* **User Journey:**  A user would typically interact with this code indirectly by including a dependency in their Meson project that requires a `.wrap` file. When Meson configures the build, it will use this `wrap.py` module to resolve and download the dependency.

**6. Structuring the Answer:**

Finally, I'd structure the answer to directly address each part of the prompt, providing clear explanations and examples where requested. I'd start with a concise summary of the file's functionality, then elaborate on the connections to reverse engineering, low-level details, logical reasoning, user errors, and the user journey.

**Self-Correction/Refinement:**

Initially, I might have focused too much on Frida, given the prompt's context. However, the code itself is clearly part of Meson. It's important to recognize this distinction. While Frida *uses* Meson, this particular file is about Meson's dependency management features. I would refine my answer to emphasize Meson's role and how it helps build projects like Frida. Also,  I'd ensure I'm providing concrete examples rather than just abstract descriptions. For instance, instead of just saying "it handles different source types," I'd list the specific types mentioned in the code (git, hg, svn, file).
这是 `frida/subprojects/frida-qml/releng/meson/mesonbuild/wrap/wrap.py` 文件的功能归纳，这个文件是 Meson 构建系统中用于处理外部依赖（通常称为 "wrap" 依赖）的关键部分。它的主要功能是自动化下载、管理和集成外部项目到当前的构建过程中。

**主要功能归纳:**

1. **解析 `.wrap` 文件:**
   - 该文件能够解析 `.wrap` 格式的配置文件。`.wrap` 文件包含了关于外部依赖的信息，例如源代码的获取方式（URL、版本、修订号）、补丁文件、提供的依赖和程序等。
   - 它通过 `configparser` 模块来读取和解析 `.wrap` 文件。
   - 能够处理 `wrap-redirect` 类型的 `.wrap` 文件，允许将依赖定义重定向到其他 `.wrap` 文件。

2. **从 WrapDB 获取依赖信息:**
   - 它能够连接到 WrapDB (`wrapdb.mesonbuild.com`)，这是一个 Meson 项目维护的外部依赖信息数据库。
   - 可以从 WrapDB 下载 `.wrap` 文件，获取最新的版本信息和 `.wrap` 文件内容。
   - 包含对 WrapDB URL 的白名单验证，确保只连接到可信的源。
   - 支持通过 HTTPS 连接到 WrapDB，如果 Python 环境支持 SSL。

3. **下载外部依赖源代码:**
   - 支持多种源代码获取方式：
     - **`file`:** 从指定的 URL 下载压缩包文件（如 zip、tar.gz）。
     - **`git`:** 克隆指定的 Git 仓库，并检出特定的修订号或分支。支持浅克隆 (`--depth`) 和递归克隆子模块。
     - **`hg`:** 克隆指定的 Mercurial 仓库，并检出特定的修订号。
     - **`svn`:** 检出指定的 Subversion 仓库的特定修订号。
   - 使用 `urllib.request` 模块进行文件下载和网络请求。
   - 可以处理需要认证的下载，支持 `.netrc` 文件来获取用户名和密码。

4. **应用补丁:**
   - 可以读取并应用 `.wrap` 文件中指定的补丁文件 (`patch_filename` 或 `patch_url`)。
   - 使用 `patch` 命令来应用补丁。
   - 支持在 `.wrap` 文件中指定多个补丁文件 (`diff_files`)。

5. **管理本地缓存:**
   - 使用 `MESON_PACKAGE_CACHE_DIR` 环境变量或默认的 `packagecache` 目录作为本地缓存。
   - 可以将下载的源代码或解压后的目录缓存到本地，避免重复下载。
   - 存储 `.wrap` 文件的哈希值，用于检测 `.wrap` 文件是否更新，并提醒用户子项目可能已过时。

6. **提供依赖和程序信息:**
   - 解析 `.wrap` 文件中的 `[provide]` 部分，记录外部依赖提供的其他依赖项和程序。
   - 允许其他 Meson 子项目或主项目通过这些信息来查找和使用这些外部依赖提供的功能。

7. **处理 Git 子模块:**
   - 可以检测并初始化 Git 子模块，确保外部依赖的 Git 子模块也被正确检出。

8. **错误处理和警告:**
   - 定义了 `WrapException` 和 `WrapNotFoundException` 等自定义异常，用于处理 wrap 相关的错误。
   - 会对潜在的安全问题（如非 HTTPS 的 WrapDB 连接）和用户配置错误发出警告。

**与逆向的方法的关系 (举例说明):**

* **获取目标软件的依赖源码:** 在逆向分析一个复杂的二进制程序时，了解其依赖的第三方库的源代码非常有帮助。通过 Meson 和 `.wrap` 文件，逆向工程师可以轻松地下载目标软件依赖的特定版本的库的源代码，例如 OpenSSL、zlib 等。这有助于理解目标软件如何使用这些库，以及可能存在的漏洞。
    * **举例:** 假设你想逆向分析一个使用了特定版本 libpng 的程序。如果该程序的构建系统是 Meson，并且提供了相应的 `.wrap` 文件，你可以通过 Meson 的命令（虽然 `wrap.py` 本身不是直接被用户调用的命令，但它是 Meson 内部处理 wrap 依赖的核心）下载该 libpng 版本的源代码，以便进行静态分析或动态调试。

* **应用补丁进行调试或修改:**  有时，为了方便调试或修改外部依赖，逆向工程师可能需要应用自定义的补丁。`wrap.py` 提供的应用补丁的功能可以直接用于将这些修改应用到下载的源代码中，然后再进行构建和分析。
    * **举例:** 你可能发现 libpng 的某个函数存在潜在的安全问题，想要在本地构建一个修复后的版本用于测试。你可以创建一个补丁文件，然后在 `.wrap` 文件中指定这个补丁，Meson 会在下载 libpng 源代码后自动应用这个补丁。

**涉及二进制底层，Linux, Android 内核及框架的知识 (举例说明):**

* **构建过程:** 虽然 `wrap.py` 本身是用 Python 编写的，不直接操作二进制，但它参与了软件的构建过程，而构建的最终产物是二进制文件。它确保了构建所需的依赖项的源代码被正确获取和准备，这是生成最终二进制文件的前提。
* **Linux 系统调用和库:**  许多通过 wrap 集成的依赖库（如 OpenSSL、libusb）最终会涉及到 Linux 系统调用和底层库的交互。`wrap.py` 确保了这些库的源代码被正确地集成到项目中，使得构建出的程序能够正常使用这些底层功能。
* **Android 框架依赖:** 在 Frida 这样的工具的构建过程中，可能需要依赖 Android 框架的某些部分或其他底层库。`wrap.py` 可以用来管理这些依赖项的获取和集成。虽然提供的代码片段没有直接体现 Android 特有的知识，但在 Frida 的构建上下文中，它可能被用于处理与 Android 相关的依赖。
* **交叉编译:**  `wrap.py` 处理的依赖项需要根据目标平台进行编译。在交叉编译的场景下（例如为 Android 构建），它确保了获取到的依赖源代码能够被配置和编译到目标平台的架构上。

**逻辑推理 (假设输入与输出):**

* **假设输入:**
    * 当前项目需要一个名为 `mylib` 的外部依赖。
    * 在 `subprojects` 目录下存在一个名为 `mylib.wrap` 的文件，内容如下：
      ```ini
      [wrap-file]
      directory = mylib-1.0
      source_url = https://example.com/mylib-1.0.tar.gz
      source_filename = mylib-1.0.tar.gz
      source_hash = 1234abcd...
      ```
* **输出:**
    * `wrap.py` 会解析 `mylib.wrap` 文件，获取源代码 URL 和文件名。
    * 它会尝试下载 `https://example.com/mylib-1.0.tar.gz` 文件到本地缓存目录（如果尚未缓存）。
    * 下载完成后，会校验文件的哈希值是否与 `source_hash` 匹配。
    * 如果校验通过，会将压缩包解压到 `subprojects/mylib-1.0` 目录。
    * Meson 构建系统后续可以使用该目录下的源代码进行编译。

**用户或编程常见的使用错误 (举例说明):**

* **错误的 `.wrap` 文件语法:** 用户可能在 `.wrap` 文件中输入错误的语法，例如拼写错误、缺少必要的字段等，导致 `configparser` 解析失败，引发 `WrapException`。
    * **举例:** 将 `source_url` 拼写成 `source_url`。
* **`source_hash` 不匹配:** 下载的源代码文件的哈希值与 `.wrap` 文件中指定的 `source_hash` 不匹配，这通常意味着下载的文件损坏或被篡改，`wrap.py` 会抛出异常。
* **网络连接问题:**  当尝试从 URL 下载源代码或 WrapDB 信息时，如果网络连接存在问题，例如 DNS 解析失败、连接超时等，会导致下载失败，`wrap.py` 会抛出异常。
* **依赖冲突:** 多个 `.wrap` 文件提供了相同的依赖项名称，导致 `Resolver` 在加载 wraps 时抛出 `WrapException`，提示存在冲突。
* **权限问题:**  没有足够的权限在缓存目录或子项目目录中创建文件或目录，导致下载或解压失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在 `meson.build` 文件中声明了一个子项目依赖:**
   ```python
   subproject('mylib')
   ```
2. **Meson 构建系统在配置阶段遇到 `subproject('mylib')`。**
3. **Meson 会查找 `subprojects/mylib` 目录或 `subprojects/mylib.wrap` 文件。**
4. **如果找到 `mylib.wrap` 文件，Meson 会调用 `wrap.py` 中的相关功能来处理这个 wrap 依赖。**
5. **`wrap.py` 会解析 `mylib.wrap` 文件，并根据其中的信息尝试下载源代码。**
6. **如果在下载、解压或应用补丁的过程中发生错误，`wrap.py` 会抛出异常，并将错误信息反馈给用户。**

**作为调试线索:** 如果用户在配置 Meson 项目时遇到与子项目相关的错误，例如找不到子项目、下载失败、哈希校验失败等，那么 `wrap.py` 的代码很可能是错误发生的地方。调试时可以关注以下几点：

* 检查 `.wrap` 文件的内容是否正确。
* 检查网络连接是否正常。
* 检查本地缓存目录是否存在以及是否有足够的权限。
* 检查是否与其他 wrap 依赖存在冲突。
* 如果涉及到补丁，检查补丁文件是否正确。

**归纳一下它的功能 (第 1 部分):**

总的来说，`frida/subprojects/frida-qml/releng/meson/mesonbuild/wrap/wrap.py` 文件的主要功能是 **作为 Meson 构建系统的一部分，负责自动化地管理和集成外部依赖项 (wraps)。** 它通过解析 `.wrap` 文件、与 WrapDB 交互、下载源代码、应用补丁以及管理本地缓存等步骤，简化了外部依赖的集成过程，使得开发者能够更方便地在他们的 Meson 项目中使用第三方库。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/wrap/wrap.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2015 The Meson development team

from __future__ import annotations

from .. import mlog
import contextlib
from dataclasses import dataclass
import urllib.request
import urllib.error
import urllib.parse
import os
import hashlib
import shutil
import tempfile
import stat
import subprocess
import sys
import configparser
import time
import typing as T
import textwrap
import json

from base64 import b64encode
from netrc import netrc
from pathlib import Path, PurePath
from functools import lru_cache

from . import WrapMode
from .. import coredata
from ..mesonlib import quiet_git, GIT, ProgressBar, MesonException, windows_proof_rmtree, Popen_safe
from ..interpreterbase import FeatureNew
from ..interpreterbase import SubProject
from .. import mesonlib

if T.TYPE_CHECKING:
    import http.client
    from typing_extensions import Literal

    Method = Literal['meson', 'cmake', 'cargo']

try:
    # Importing is just done to check if SSL exists, so all warnings
    # regarding 'imported but unused' can be safely ignored
    import ssl  # noqa
    has_ssl = True
except ImportError:
    has_ssl = False

REQ_TIMEOUT = 30.0
WHITELIST_SUBDOMAIN = 'wrapdb.mesonbuild.com'

ALL_TYPES = ['file', 'git', 'hg', 'svn']

PATCH = shutil.which('patch')

def whitelist_wrapdb(urlstr: str) -> urllib.parse.ParseResult:
    """ raises WrapException if not whitelisted subdomain """
    url = urllib.parse.urlparse(urlstr)
    if not url.hostname:
        raise WrapException(f'{urlstr} is not a valid URL')
    if not url.hostname.endswith(WHITELIST_SUBDOMAIN):
        raise WrapException(f'{urlstr} is not a whitelisted WrapDB URL')
    if has_ssl and not url.scheme == 'https':
        raise WrapException(f'WrapDB did not have expected SSL https url, instead got {urlstr}')
    return url

def open_wrapdburl(urlstring: str, allow_insecure: bool = False, have_opt: bool = False) -> 'http.client.HTTPResponse':
    if have_opt:
        insecure_msg = '\n\n    To allow connecting anyway, pass `--allow-insecure`.'
    else:
        insecure_msg = ''

    url = whitelist_wrapdb(urlstring)
    if has_ssl:
        try:
            return T.cast('http.client.HTTPResponse', urllib.request.urlopen(urllib.parse.urlunparse(url), timeout=REQ_TIMEOUT))
        except urllib.error.URLError as excp:
            msg = f'WrapDB connection failed to {urlstring} with error {excp}.'
            if isinstance(excp.reason, ssl.SSLCertVerificationError):
                if allow_insecure:
                    mlog.warning(f'{msg}\n\n    Proceeding without authentication.')
                else:
                    raise WrapException(f'{msg}{insecure_msg}')
            else:
                raise WrapException(msg)
    elif not allow_insecure:
        raise WrapException(f'SSL module not available in {sys.executable}: Cannot contact the WrapDB.{insecure_msg}')
    else:
        # following code is only for those without Python SSL
        mlog.warning(f'SSL module not available in {sys.executable}: WrapDB traffic not authenticated.', once=True)

    # If we got this far, allow_insecure was manually passed
    nossl_url = url._replace(scheme='http')
    try:
        return T.cast('http.client.HTTPResponse', urllib.request.urlopen(urllib.parse.urlunparse(nossl_url), timeout=REQ_TIMEOUT))
    except urllib.error.URLError as excp:
        raise WrapException(f'WrapDB connection failed to {urlstring} with error {excp}')

def get_releases_data(allow_insecure: bool) -> bytes:
    url = open_wrapdburl('https://wrapdb.mesonbuild.com/v2/releases.json', allow_insecure, True)
    return url.read()

@lru_cache(maxsize=None)
def get_releases(allow_insecure: bool) -> T.Dict[str, T.Any]:
    data = get_releases_data(allow_insecure)
    return T.cast('T.Dict[str, T.Any]', json.loads(data.decode()))

def update_wrap_file(wrapfile: str, name: str, new_version: str, new_revision: str, allow_insecure: bool) -> None:
    url = open_wrapdburl(f'https://wrapdb.mesonbuild.com/v2/{name}_{new_version}-{new_revision}/{name}.wrap',
                         allow_insecure, True)
    with open(wrapfile, 'wb') as f:
        f.write(url.read())

def parse_patch_url(patch_url: str) -> T.Tuple[str, str]:
    u = urllib.parse.urlparse(patch_url)
    if u.netloc != 'wrapdb.mesonbuild.com':
        raise WrapException(f'URL {patch_url} does not seems to be a wrapdb patch')
    arr = u.path.strip('/').split('/')
    if arr[0] == 'v1':
        # e.g. https://wrapdb.mesonbuild.com/v1/projects/zlib/1.2.11/5/get_zip
        return arr[-3], arr[-2]
    elif arr[0] == 'v2':
        # e.g. https://wrapdb.mesonbuild.com/v2/zlib_1.2.11-5/get_patch
        tag = arr[-2]
        _, version = tag.rsplit('_', 1)
        version, revision = version.rsplit('-', 1)
        return version, revision
    else:
        raise WrapException(f'Invalid wrapdb URL {patch_url}')

class WrapException(MesonException):
    pass

class WrapNotFoundException(WrapException):
    pass

class PackageDefinition:
    def __init__(self, fname: str, subproject: str = ''):
        self.filename = fname
        self.subproject = SubProject(subproject)
        self.type: T.Optional[str] = None
        self.values: T.Dict[str, str] = {}
        self.provided_deps: T.Dict[str, T.Optional[str]] = {}
        self.provided_programs: T.List[str] = []
        self.diff_files: T.List[Path] = []
        self.basename = os.path.basename(fname)
        self.has_wrap = self.basename.endswith('.wrap')
        self.name = self.basename[:-5] if self.has_wrap else self.basename
        # must be lowercase for consistency with dep=variable assignment
        self.provided_deps[self.name.lower()] = None
        # What the original file name was before redirection
        self.original_filename = fname
        self.redirected = False
        if self.has_wrap:
            self.parse_wrap()
            with open(fname, 'r', encoding='utf-8') as file:
                self.wrapfile_hash = hashlib.sha256(file.read().encode('utf-8')).hexdigest()
        self.directory = self.values.get('directory', self.name)
        if os.path.dirname(self.directory):
            raise WrapException('Directory key must be a name and not a path')
        if self.type and self.type not in ALL_TYPES:
            raise WrapException(f'Unknown wrap type {self.type!r}')
        self.filesdir = os.path.join(os.path.dirname(self.filename), 'packagefiles')

    def parse_wrap(self) -> None:
        try:
            config = configparser.ConfigParser(interpolation=None)
            config.read(self.filename, encoding='utf-8')
        except configparser.Error as e:
            raise WrapException(f'Failed to parse {self.basename}: {e!s}')
        self.parse_wrap_section(config)
        if self.type == 'redirect':
            # [wrap-redirect] have a `filename` value pointing to the real wrap
            # file we should parse instead. It must be relative to the current
            # wrap file location and must be in the form foo/subprojects/bar.wrap.
            dirname = Path(self.filename).parent
            fname = Path(self.values['filename'])
            for i, p in enumerate(fname.parts):
                if i % 2 == 0:
                    if p == '..':
                        raise WrapException('wrap-redirect filename cannot contain ".."')
                else:
                    if p != 'subprojects':
                        raise WrapException('wrap-redirect filename must be in the form foo/subprojects/bar.wrap')
            if fname.suffix != '.wrap':
                raise WrapException('wrap-redirect filename must be a .wrap file')
            fname = dirname / fname
            if not fname.is_file():
                raise WrapException(f'wrap-redirect {fname} filename does not exist')
            self.filename = str(fname)
            self.parse_wrap()
            self.redirected = True
        else:
            self.parse_provide_section(config)
        if 'patch_directory' in self.values:
            FeatureNew('Wrap files with patch_directory', '0.55.0').use(self.subproject)
        for what in ['patch', 'source']:
            if f'{what}_filename' in self.values and f'{what}_url' not in self.values:
                FeatureNew(f'Local wrap patch files without {what}_url', '0.55.0').use(self.subproject)

    def parse_wrap_section(self, config: configparser.ConfigParser) -> None:
        if len(config.sections()) < 1:
            raise WrapException(f'Missing sections in {self.basename}')
        self.wrap_section = config.sections()[0]
        if not self.wrap_section.startswith('wrap-'):
            raise WrapException(f'{self.wrap_section!r} is not a valid first section in {self.basename}')
        self.type = self.wrap_section[5:]
        self.values = dict(config[self.wrap_section])
        if 'diff_files' in self.values:
            FeatureNew('Wrap files with diff_files', '0.63.0').use(self.subproject)
            for s in self.values['diff_files'].split(','):
                path = Path(s.strip())
                if path.is_absolute():
                    raise WrapException('diff_files paths cannot be absolute')
                if '..' in path.parts:
                    raise WrapException('diff_files paths cannot contain ".."')
                self.diff_files.append(path)

    def parse_provide_section(self, config: configparser.ConfigParser) -> None:
        if config.has_section('provides'):
            raise WrapException('Unexpected "[provides]" section, did you mean "[provide]"?')
        if config.has_section('provide'):
            for k, v in config['provide'].items():
                if k == 'dependency_names':
                    # A comma separated list of dependency names that does not
                    # need a variable name; must be lowercase for consistency with
                    # dep=variable assignment
                    names_dict = {n.strip().lower(): None for n in v.split(',')}
                    self.provided_deps.update(names_dict)
                    continue
                if k == 'program_names':
                    # A comma separated list of program names
                    names_list = [n.strip() for n in v.split(',')]
                    self.provided_programs += names_list
                    continue
                if not v:
                    m = (f'Empty dependency variable name for {k!r} in {self.basename}. '
                         'If the subproject uses meson.override_dependency() '
                         'it can be added in the "dependency_names" special key.')
                    raise WrapException(m)
                self.provided_deps[k] = v

    def get(self, key: str) -> str:
        try:
            return self.values[key]
        except KeyError:
            raise WrapException(f'Missing key {key!r} in {self.basename}')

    def get_hashfile(self, subproject_directory: str) -> str:
        return os.path.join(subproject_directory, '.meson-subproject-wrap-hash.txt')

    def update_hash_cache(self, subproject_directory: str) -> None:
        if self.has_wrap:
            with open(self.get_hashfile(subproject_directory), 'w', encoding='utf-8') as file:
                file.write(self.wrapfile_hash + '\n')

def get_directory(subdir_root: str, packagename: str) -> str:
    fname = os.path.join(subdir_root, packagename + '.wrap')
    if os.path.isfile(fname):
        wrap = PackageDefinition(fname)
        return wrap.directory
    return packagename

def verbose_git(cmd: T.List[str], workingdir: str, check: bool = False) -> bool:
    '''
    Wrapper to convert GitException to WrapException caught in interpreter.
    '''
    try:
        return mesonlib.verbose_git(cmd, workingdir, check=check)
    except mesonlib.GitException as e:
        raise WrapException(str(e))

@dataclass(eq=False)
class Resolver:
    source_dir: str
    subdir: str
    subproject: str = ''
    wrap_mode: WrapMode = WrapMode.default
    wrap_frontend: bool = False
    allow_insecure: bool = False
    silent: bool = False

    def __post_init__(self) -> None:
        self.subdir_root = os.path.join(self.source_dir, self.subdir)
        self.cachedir = os.environ.get('MESON_PACKAGE_CACHE_DIR') or os.path.join(self.subdir_root, 'packagecache')
        self.wraps: T.Dict[str, PackageDefinition] = {}
        self.netrc: T.Optional[netrc] = None
        self.provided_deps: T.Dict[str, PackageDefinition] = {}
        self.provided_programs: T.Dict[str, PackageDefinition] = {}
        self.wrapdb: T.Dict[str, T.Any] = {}
        self.wrapdb_provided_deps: T.Dict[str, str] = {}
        self.wrapdb_provided_programs: T.Dict[str, str] = {}
        self.load_wraps()
        self.load_netrc()
        self.load_wrapdb()

    def load_netrc(self) -> None:
        try:
            self.netrc = netrc()
        except FileNotFoundError:
            return
        except Exception as e:
            mlog.warning(f'failed to process netrc file: {e}.', fatal=False)

    def load_wraps(self) -> None:
        if not os.path.isdir(self.subdir_root):
            return
        root, dirs, files = next(os.walk(self.subdir_root))
        ignore_dirs = {'packagecache', 'packagefiles'}
        for i in files:
            if not i.endswith('.wrap'):
                continue
            fname = os.path.join(self.subdir_root, i)
            wrap = PackageDefinition(fname, self.subproject)
            self.wraps[wrap.name] = wrap
            ignore_dirs |= {wrap.directory, wrap.name}
        # Add dummy package definition for directories not associated with a wrap file.
        for i in dirs:
            if i in ignore_dirs:
                continue
            fname = os.path.join(self.subdir_root, i)
            wrap = PackageDefinition(fname, self.subproject)
            self.wraps[wrap.name] = wrap

        for wrap in self.wraps.values():
            self.add_wrap(wrap)

    def add_wrap(self, wrap: PackageDefinition) -> None:
        for k in wrap.provided_deps.keys():
            if k in self.provided_deps:
                prev_wrap = self.provided_deps[k]
                m = f'Multiple wrap files provide {k!r} dependency: {wrap.basename} and {prev_wrap.basename}'
                raise WrapException(m)
            self.provided_deps[k] = wrap
        for k in wrap.provided_programs:
            if k in self.provided_programs:
                prev_wrap = self.provided_programs[k]
                m = f'Multiple wrap files provide {k!r} program: {wrap.basename} and {prev_wrap.basename}'
                raise WrapException(m)
            self.provided_programs[k] = wrap

    def load_wrapdb(self) -> None:
        try:
            with Path(self.subdir_root, 'wrapdb.json').open('r', encoding='utf-8') as f:
                self.wrapdb = json.load(f)
        except FileNotFoundError:
            return
        for name, info in self.wrapdb.items():
            self.wrapdb_provided_deps.update({i: name for i in info.get('dependency_names', [])})
            self.wrapdb_provided_programs.update({i: name for i in info.get('program_names', [])})

    def get_from_wrapdb(self, subp_name: str) -> T.Optional[PackageDefinition]:
        info = self.wrapdb.get(subp_name)
        if not info:
            return None
        self.check_can_download()
        latest_version = info['versions'][0]
        version, revision = latest_version.rsplit('-', 1)
        url = urllib.request.urlopen(f'https://wrapdb.mesonbuild.com/v2/{subp_name}_{version}-{revision}/{subp_name}.wrap')
        fname = Path(self.subdir_root, f'{subp_name}.wrap')
        with fname.open('wb') as f:
            f.write(url.read())
        mlog.log(f'Installed {subp_name} version {version} revision {revision}')
        wrap = PackageDefinition(str(fname))
        self.wraps[wrap.name] = wrap
        self.add_wrap(wrap)
        return wrap

    def merge_wraps(self, other_resolver: 'Resolver') -> None:
        for k, v in other_resolver.wraps.items():
            self.wraps.setdefault(k, v)
        for k, v in other_resolver.provided_deps.items():
            self.provided_deps.setdefault(k, v)
        for k, v in other_resolver.provided_programs.items():
            self.provided_programs.setdefault(k, v)

    def find_dep_provider(self, packagename: str) -> T.Tuple[T.Optional[str], T.Optional[str]]:
        # Python's ini parser converts all key values to lowercase.
        # Thus the query name must also be in lower case.
        packagename = packagename.lower()
        wrap = self.provided_deps.get(packagename)
        if wrap:
            dep_var = wrap.provided_deps.get(packagename)
            return wrap.name, dep_var
        wrap_name = self.wrapdb_provided_deps.get(packagename)
        return wrap_name, None

    def get_varname(self, subp_name: str, depname: str) -> T.Optional[str]:
        wrap = self.wraps.get(subp_name)
        return wrap.provided_deps.get(depname) if wrap else None

    def find_program_provider(self, names: T.List[str]) -> T.Optional[str]:
        for name in names:
            wrap = self.provided_programs.get(name)
            if wrap:
                return wrap.name
            wrap_name = self.wrapdb_provided_programs.get(name)
            if wrap_name:
                return wrap_name
        return None

    def resolve(self, packagename: str, force_method: T.Optional[Method] = None) -> T.Tuple[str, Method]:
        wrap = self.wraps.get(packagename)
        if wrap is None:
            wrap = self.get_from_wrapdb(packagename)
            if wrap is None:
                raise WrapNotFoundException(f'Neither a subproject directory nor a {packagename}.wrap file was found.')
        self.wrap = wrap
        self.directory = self.wrap.directory

        if self.wrap.has_wrap:
            # We have a .wrap file, use directory relative to the location of
            # the wrap file if it exists, otherwise source code will be placed
            # into main project's subproject_dir even if the wrap file comes
            # from another subproject.
            self.dirname = os.path.join(os.path.dirname(self.wrap.filename), self.wrap.directory)
            if not os.path.exists(self.dirname):
                self.dirname = os.path.join(self.subdir_root, self.directory)
            # Check if the wrap comes from the main project.
            main_fname = os.path.join(self.subdir_root, self.wrap.basename)
            if self.wrap.filename != main_fname:
                rel = os.path.relpath(self.wrap.filename, self.source_dir)
                mlog.log('Using', mlog.bold(rel))
                # Write a dummy wrap file in main project that redirect to the
                # wrap we picked.
                with open(main_fname, 'w', encoding='utf-8') as f:
                    f.write(textwrap.dedent(f'''\
                        [wrap-redirect]
                        filename = {PurePath(os.path.relpath(self.wrap.filename, self.subdir_root)).as_posix()}
                        '''))
        else:
            # No wrap file, it's a dummy package definition for an existing
            # directory. Use the source code in place.
            self.dirname = self.wrap.filename
        rel_path = os.path.relpath(self.dirname, self.source_dir)

        # Map each supported method to a file that must exist at the root of source tree.
        methods_map: T.Dict[Method, str] = {
            'meson': 'meson.build',
            'cmake': 'CMakeLists.txt',
            'cargo': 'Cargo.toml',
        }

        # Check if this wrap forces a specific method, use meson otherwise.
        method = T.cast('T.Optional[Method]', self.wrap.values.get('method', force_method))
        if method and method not in methods_map:
            allowed_methods = ', '.join(methods_map.keys())
            raise WrapException(f'Wrap method {method!r} is not supported, must be one of: {allowed_methods}')
        if force_method and method != force_method:
            raise WrapException(f'Wrap method is {method!r} but we are trying to configure it with {force_method}')
        method = method or 'meson'

        def has_buildfile() -> bool:
            return os.path.exists(os.path.join(self.dirname, methods_map[method]))

        # The directory is there and has meson.build? Great, use it.
        if has_buildfile():
            self.validate()
            return rel_path, method

        # Check if the subproject is a git submodule
        self.resolve_git_submodule()

        if os.path.exists(self.dirname):
            if not os.path.isdir(self.dirname):
                raise WrapException('Path already exists but is not a directory')
        else:
            # Check first if we have the extracted directory in our cache. This can
            # happen for example when MESON_PACKAGE_CACHE_DIR=/usr/share/cargo/registry
            # on distros that ships Rust source code.
            # TODO: We don't currently clone git repositories into the cache
            # directory, but we should to avoid cloning multiple times the same
            # repository. In that case, we could do something smarter than
            # copy_tree() here.
            cached_directory = os.path.join(self.cachedir, self.directory)
            if os.path.isdir(cached_directory):
                self.copy_tree(cached_directory, self.dirname)
            elif self.wrap.type == 'file':
                self._get_file(packagename)
            else:
                self.check_can_download()
                if self.wrap.type == 'git':
                    self._get_git(packagename)
                elif self.wrap.type == "hg":
                    self._get_hg()
                elif self.wrap.type == "svn":
                    self._get_svn()
                else:
                    raise WrapException(f'Unknown wrap type {self.wrap.type!r}')
            try:
                self.apply_patch(packagename)
                self.apply_diff_files()
            except Exception:
                windows_proof_rmtree(self.dirname)
                raise

        if not has_buildfile():
            raise WrapException(f'Subproject exists but has no {methods_map[method]} file.')

        # At this point, the subproject has been successfully resolved for the
        # first time so save off the hash of the entire wrap file for future
        # reference.
        self.wrap.update_hash_cache(self.dirname)
        return rel_path, method

    def check_can_download(self) -> None:
        # Don't download subproject data based on wrap file if requested.
        # Git submodules are ok (see above)!
        if self.wrap_mode is WrapMode.nodownload:
            m = 'Automatic wrap-based subproject downloading is disabled'
            raise WrapException(m)

    def resolve_git_submodule(self) -> bool:
        # Is git installed? If not, we're probably not in a git repository and
        # definitely cannot try to conveniently set up a submodule.
        if not GIT:
            return False
        # Does the directory exist? Even uninitialised submodules checkout an
        # empty directory to work in
        if not os.path.isdir(self.dirname):
            return False
        # Are we in a git repository?
        ret, out = quiet_git(['rev-parse'], Path(self.dirname).parent)
        if not ret:
            return False
        # Is `dirname` a submodule?
        ret, out = quiet_git(['submodule', 'status', '.'], self.dirname)
        if not ret:
            return False
        # Submodule has not been added, add it
        if out.startswith('+'):
            mlog.warning('git submodule might be out of date')
            return True
        elif out.startswith('U'):
            raise WrapException('git submodule has merge conflicts')
        # Submodule exists, but is deinitialized or wasn't initialized
        elif out.startswith('-'):
            if verbose_git(['submodule', 'update', '--init', '.'], self.dirname):
                return True
            raise WrapException('git submodule failed to init')
        # Submodule looks fine, but maybe it wasn't populated properly. Do a checkout.
        elif out.startswith(' '):
            verbose_git(['submodule', 'update', '.'], self.dirname)
            verbose_git(['checkout', '.'], self.dirname)
            # Even if checkout failed, try building it anyway and let the user
            # handle any problems manually.
            return True
        elif out == '':
            # It is not a submodule, just a folder that exists in the main repository.
            return False
        raise WrapException(f'Unknown git submodule output: {out!r}')

    def _get_file(self, packagename: str) -> None:
        path = self._get_file_internal('source', packagename)
        extract_dir = self.subdir_root
        # Some upstreams ship packages that do not have a leading directory.
        # Create one for them.
        if 'lead_directory_missing' in self.wrap.values:
            os.mkdir(self.dirname)
            extract_dir = self.dirname
        try:
            shutil.unpack_archive(path, extract_dir)
        except OSError as e:
            raise WrapException(f'failed to unpack archive with error: {str(e)}') from e

    def _get_git(self, packagename: str) -> None:
        if not GIT:
            raise WrapException(f'Git program not found, cannot download {packagename}.wrap via git.')
        revno = self.wrap.get('revision')
        checkout_cmd = ['-c', 'advice.detachedHead=false', 'checkout', revno, '--']
        is_shallow = False
        depth_option: T.List[str] = []
        if self.wrap.values.get('depth', '') != '':
            is_shallow = True
            depth_option = ['--depth', self.wrap.values.get('depth')]
        # for some reason git only allows commit ids to be shallowly fetched by fetch not with clone
        if is_shallow and self.is_git_full_commit_id(revno):
            # git doesn't support directly cloning shallowly for commits,
            # so we follow https://stackoverflow.com/a/43136160
            verbose_git(['-c', 'init.defaultBranch=meson-dummy-branch', 'init', self.directory], self.subdir_root, check=True)
            verbose_git(['remote', 'add', 'origin', self.wrap.get('url')], self.dirname, check=True)
            revno = self.wrap.get('revision')
            verbose_git(['fetch', *depth_option, 'origin', revno], self.dirname, check=True)
            verbose_git(checkout_cmd, self.dirname, check=True)
        else:
            if not is_shallow:
                verbose_git(['clone', self.wrap.get('url'), self.directory], self.subdir_root, check=True)
                if revno.lower() != 'head':
                    if not verbose_git(checkout_cmd, self.dirname):
                        verbose_git(['fetch', self.wrap.get('url'), revno], self.dirname, check=True)
                        verbose_git(checkout_cmd, self.dirname, check=True)
            else:
                args = ['-c', 'advice.detachedHead=false', 'clone', *depth_option]
                if revno.lower() != 'head':
                    args += ['--branch', revno]
                args += [self.wrap.get('url'), self.directory]
                verbose_git(args, self.subdir_root, check=True)
        if self.wrap.values.get('clone-recursive', '').lower() == 'true':
            verbose_git(['submodule', 'update', '--init', '--checkout', '--recursive', *depth_option],
                        self.dirname, check=True)
        push_url = self.wrap.values.get('push-url')
        if push_url:
            verbose_git(['remote', 'set-url', '--push', 'origin', push_url], self.dirname, check=True)

    def validate(self) -> None:
        # This check is only for subprojects with wraps.
        if not self.wrap.has_wrap:
            return

        # Retrieve original hash, if it exists.
        hashfile = self.wrap.get_hashfile(self.dirname)
        if os.path.isfile(hashfile):
            with open(hashfile, 'r', encoding='utf-8') as file:
                expected_hash = file.read().strip()
        else:
            # If stored hash doesn't exist then don't warn.
            return

        actual_hash = self.wrap.wrapfile_hash

        # Compare hashes and warn the user if they don't match.
        if expected_hash != actual_hash:
            mlog.warning(f'Subproject {self.wrap.name}\'s revision may be out of date; its wrap file has changed since it was first configured')

    def is_git_full_commit_id(self, revno: str) -> bool:
        result = False
        if len(revno) in {40, 64}: # 40 for sha1, 64 for upcoming sha256
            result = all(ch in '0123456789AaBbCcDdEeFf' for ch in revno)
        return result

    def _get_hg(self) -> None:
        revno = self.wrap.get('revision')
        hg = shutil.which('hg')
        if not hg:
            raise WrapException('Mercurial program not found.')
        subprocess.check_call([hg, 'clone', self.wrap.get('url'),
                               self.directory], cwd=self.subdir_root)
        if revno.lower() != 'tip':
            subprocess.check_call([hg, 'checkout', revno],
                                  cwd=self.dirname)

    def _get_svn(self) -> None:
        revno = self.wrap.get('revision')
        svn = shutil.which('svn')
        if not svn:
            raise WrapException('SVN program not found.')
        subprocess.check_call([svn, 'checkout', '-r', revno, self.wrap.get('url'),
                               self.directory], cwd=self.subdir_root)

    def get_netrc_credentials(self, netloc: str) -> T.Optional[T.Tuple[str, str]]:
        if self.netrc is None or netloc not in self.netrc.hosts:
            return None

        login, account, password = self.netrc.authenticators(netloc)
        if account is not None:
            login = account

        return login, password

    def get_data(self, urlstring: str) -> T.Tuple[str, str]:
        blocksize = 10 * 1024
        h = hashlib.sha256()
        tmpfile = tempfile.NamedTemporaryFile(mode='wb', dir=self.cachedir, delete=False)
        url = urllib.parse.urlparse(urlstring)
        if url.hostname and url.hostname.endswith(WHITELIST_SUBDOMAIN):
            resp = open_wrapdburl(urlstring, allow_insecure=self.allow_insecure, have_opt=self.wrap_frontend)
        elif WHITELIST_SUBDOMAIN in urlstring:
            raise WrapException(f'{urlstring} may be a WrapDB-impersonating URL')
        else:
            headers = {'User-Agent': f'mesonbuild/{coredata.version}'}
            creds = self.get_netrc_credentials(url.netloc)

            if creds is not None and '@' not in url.netloc:
                login, password = creds
                if url.scheme == 'https':
                    enc_creds = b64encode(f'{login}:{password}'.encode()).decode()
                    headers.update({'Authorization': f'Basic {enc_creds}'})
                elif url.scheme == 'ftp':
                    urlstring = urllib.parse.urlunparse(url._replace(netloc=f'{login}:{password}@{url.netloc}'))
                else:
                    mlog.warning('Meson is not going to use netrc credentials for protocols other than https/ftp',
                                 fatal=False)

            try:
                req = urllib.request.Request(urlstring, headers=headers)
                resp = urllib.request.urlopen(req, timeout=REQ_TIMEOUT)
            except urllib.error.URLError as e:
                mlog.log(str(e))
                raise WrapException(f'could not get {urlstring} is the internet available?')
        with contextlib.closing(resp) as resp, tmpfile as tmpfile:
            try:
                dlsize = int(resp.info()['Content-Length'])
            except TypeError:
                dlsize = None
            if dlsize is None:
                print('Downloading file of unknown size.')
                while True:
                    block = resp.read(blocksize)
                    if block == b'':
                        break
                    h.update(block)
                    tmpfile.write(block)
                hashvalue = h.hexdigest()
                return hashvalue, tmpfile.name
            sys.stdout.flush()
            progress_bar = ProgressBar(bar_type='download', total=dlsize,
                                       desc='Downloading',
                                       disable=(self.silent or None))
            while True:
                block = resp.read(blocksize)
                if block == b'':
                    break
                h.update(block)
                tmpfile.write(block)
                progress_bar.update(len(block))
            progress_bar.close()
            hashvalue = h.hexdigest()
        return hashvalue, tmpfile.name

    def check_hash(self, what: str, path: str, hash_required:
```