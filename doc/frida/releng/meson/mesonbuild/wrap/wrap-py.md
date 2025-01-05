Response:
The user wants a summary of the functionality of the Python code provided. The code seems to be part of the `frida` project, specifically related to handling external dependencies using a system called "wrap". I need to analyze the code and identify its key responsibilities.

Here's a breakdown of the code's functionality based on a quick scan:

1. **Wrap File Handling:** The code parses and interprets `.wrap` files, which seem to describe how to obtain and integrate external dependencies.
2. **Dependency Resolution:** It resolves dependencies declared in `.wrap` files, potentially downloading source code or applying patches.
3. **WrapDB Interaction:** It interacts with a "WrapDB" (likely a repository of `.wrap` files) to find and download dependency information.
4. **Source Code Management:**  It handles different types of source code retrieval (file downloads, Git, Mercurial, SVN).
5. **Patch Application:** It applies patches to the downloaded source code.
6. **Caching:** It uses a cache to store downloaded packages to avoid redundant downloads.
7. **Git Submodule Handling:** It can manage dependencies that are Git submodules.
8. **Security:** It includes checks to ensure interaction with the official WrapDB.
9. **Error Handling:** It defines custom exceptions for wrap-related errors.

Now, I need to organize these points into a concise summary for part 1 of the response.
好的，这是 `frida/releng/meson/mesonbuild/wrap/wrap.py` 文件的功能归纳：

该 Python 文件主要负责 **处理和管理外部依赖项 (subprojects) 的 "wrap" 文件**，以便在 Frida 的构建过程中集成这些依赖。 其核心功能可以概括为：

1. **解析 `.wrap` 文件：**  它能够读取和解析 `.wrap` 格式的配置文件，这些文件包含了如何获取、验证和集成外部依赖项的信息。这些信息包括依赖项的来源（文件、Git 仓库、Mercurial 仓库、SVN 仓库）、版本、修订号、校验和、补丁信息等。

2. **从 WrapDB 获取信息：** 它可以与一个名为 "WrapDB" 的在线仓库 (`wrapdb.mesonbuild.com`) 进行交互，获取可用的依赖项信息，包括最新的版本和对应的 `.wrap` 文件。

3. **下载依赖项：**  根据 `.wrap` 文件中指定的类型和 URL，它能够下载依赖项的源代码或预编译的包。支持多种下载方式，包括直接下载文件、克隆 Git 仓库、克隆 Mercurial 仓库、检出 SVN 仓库。

4. **验证下载的文件：**  它可以根据 `.wrap` 文件中提供的哈希值（如 SHA256）来验证下载的文件的完整性，防止下载损坏或被篡改的文件。

5. **应用补丁：**  如果 `.wrap` 文件中指定了补丁文件，它可以将这些补丁应用到下载的源代码中。

6. **处理 Git 子模块：**  它可以识别并初始化/更新作为 Git 子模块存在的依赖项。

7. **缓存机制：**  它使用缓存来存储下载的包和 `.wrap` 文件的哈希值，以避免重复下载和处理，提高构建效率。

8. **处理 `wrap-redirect`：** 支持 `.wrap` 文件的重定向功能，允许一个 `.wrap` 文件指向另一个 `.wrap` 文件。

9. **提供依赖信息：**  它可以提取 `.wrap` 文件中提供的依赖项名称和程序名称，用于后续的依赖查找和链接。

10. **错误处理：** 定义了专门的异常类 (`WrapException`, `WrapNotFoundException`) 来处理 wrap 相关的错误。

**简而言之，该文件的主要目标是自动化外部依赖项的获取、验证和集成过程，使得 Frida 的构建过程更加可靠和高效。**

后续的部分应该会深入到这些功能的具体实现细节。

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/wrap/wrap.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
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
"""


```