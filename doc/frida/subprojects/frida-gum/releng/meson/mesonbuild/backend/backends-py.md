Response:
The user wants a summary of the functionality of the provided Python code. I need to go through the code and identify the key data structures, classes, and methods, and explain their purpose. Since this is part 1 of 4, I should focus on the overall structure and core functionalities introduced in this segment.

Here's a breakdown of the code and its functionalities:

1. **Imports:** The code imports various standard Python libraries and modules from the `mesonbuild` package. These imports suggest the code is involved in build system logic.

2. **Type Hinting:**  Extensive use of type hints (`typing` module) indicates a focus on code clarity and maintainability, and suggests this code interacts with complex data structures.

3. **Data Classes:** Several `@dataclass` decorated classes are defined. These are likely used to represent structured data related to the build process:
    *   `RegenInfo`: Information for build system regeneration.
    *   `TestProtocol`: Enumeration for different test result formats.
    *   `CleanTrees`: Directories needing manual cleanup after a build.
    *   `InstallData`:  Data related to the installation process.
    *   `TargetInstallData`: Specific installation information for a target (executable, library, etc.).
    *   `InstallEmptyDir`: Information for installing empty directories.
    *   `InstallDataBase`: Base class for installation data (files, headers, etc.).
    *   `InstallSymlinkData`: Information for installing symbolic links.
    *   `SubdirInstallData`: Information for installing subdirectories.
    *   `TestSerialisation`: Data needed to serialize and run tests.

4. **Constants:** The `LANGS_CANT_UNITY` tuple likely defines languages that cannot participate in unity builds (a compilation optimization).

5. **Functions:**
    *   `get_backend_from_name`:  A factory function to create backend objects based on a provided name (e.g., 'ninja', 'vs2022'). This suggests the code handles different build system backends.
    *   `get_genvslite_backend`:  Similar to `get_backend_from_name`, but specifically for a "genvslite" variant of a backend.

6. **`Backend` Class:** This is the core class, likely providing common functionalities for all build backends. It includes methods for:
    *   Initialization with `build` and `interpreter` objects.
    *   `generate`:  A method that backends must implement to generate build files.
    *   Methods to get file paths relative to the build and source directories (`get_target_filename`, `get_target_filename_abs`, etc.).
    *   Methods to retrieve include arguments for compilers (`get_source_dir_include_args`, `get_build_dir_include_args`).
    *   Methods related to linking (`get_target_filename_for_linking`).
    *   Methods to determine target directories (`get_target_dir`, `get_target_dir_relative_to`).
    *   Methods for handling generated sources and unity builds (`get_target_generated_dir`, `get_unity_source_file`, `generate_unity_files`).
    *   Methods for flattening object lists for linking (`flatten_object_list`).
    *   Methods for handling Swift dependencies (`is_swift_target`, `determine_swift_dep_dirs`).
    *   Methods for serializing executable commands for later execution (`get_executable_serialisation`, `as_meson_exe_cmdline`).
    *   Methods for serializing test information (`serialize_tests`).
    *   Methods related to linkers and standard libraries (`determine_linker_and_stdlib_args`).
    *   Methods for determining rpath directories (`get_external_rpath_dirs`, `get_rpath_dirs_from_link_args`).

**Overall Functionality:**

This Python code defines the base class and supporting data structures for different build system backends within the Frida dynamic instrumentation tool. It provides abstractions and utilities for managing the build process, including handling target dependencies, generating build files, managing include paths, linking, and running tests. The code appears to be a core component of Frida's build system, responsible for translating the high-level build definitions into the specific instructions understood by underlying build tools like Ninja or Visual Studio.
```python
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2016 The Meson development team

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, InitVar
from functools import lru_cache
from itertools import chain
from pathlib import Path
import copy
import enum
import json
import os
import pickle
import re
import shlex
import shutil
import typing as T
import hashlib

from .. import build
from .. import dependencies
from .. import programs
from .. import mesonlib
from .. import mlog
from ..compilers import LANGUAGES_USING_LDFLAGS, detect
from ..mesonlib import (
    File, MachineChoice, MesonException, OrderedSet,
    ExecutableSerialisation, classify_unity_sources, OptionKey
)

if T.TYPE_CHECKING:
    from .._typing import ImmutableListProtocol
    from ..arglist import CompilerArgs
    from ..compilers import Compiler
    from ..environment import Environment
    from ..interpreter import Interpreter, Test
    from ..linkers.linkers import StaticLinker
    from ..mesonlib import FileMode, FileOrString

    from typing_extensions import TypedDict

    _ALL_SOURCES_TYPE = T.List[T.Union[File, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList]]

    class TargetIntrospectionData(TypedDict):

        language: str
        compiler: T.List[str]
        parameters: T.List[str]
        sources: T.List[str]
        generated_sources: T.List[str]

# Languages that can mix with C or C++ but don't support unity builds yet
# because the syntax we use for unity builds is specific to C/++/ObjC/++.
# Assembly files cannot be unitified and neither can LLVM IR files
LANGS_CANT_UNITY = ('d', 'fortran', 'vala')

@dataclass(eq=False)
class RegenInfo:
    source_dir: str
    build_dir: str
    depfiles: T.List[str]

class TestProtocol(enum.Enum):

    EXITCODE = 0
    TAP = 1
    GTEST = 2
    RUST = 3

    @classmethod
    def from_str(cls, string: str) -> 'TestProtocol':
        if string == 'exitcode':
            return cls.EXITCODE
        elif string == 'tap':
            return cls.TAP
        elif string == 'gtest':
            return cls.GTEST
        elif string == 'rust':
            return cls.RUST
        raise MesonException(f'unknown test format {string}')

    def __str__(self) -> str:
        cls = type(self)
        if self is cls.EXITCODE:
            return 'exitcode'
        elif self is cls.GTEST:
            return 'gtest'
        elif self is cls.RUST:
            return 'rust'
        return 'tap'

@dataclass(eq=False)
class CleanTrees:
    '''
    Directories outputted by custom targets that have to be manually cleaned
    because on Linux `ninja clean` only deletes empty directories.
    '''
    build_dir: str
    trees: T.List[str]

@dataclass(eq=False)
class InstallData:
    source_dir: str
    build_dir: str
    prefix: str
    libdir: str
    strip_bin: T.List[str]
    # TODO: in python 3.8 or with typing_Extensions this could be:
    # `T.Union[T.Literal['preserve'], int]`, which would be more accurate.
    install_umask: T.Union[str, int]
    mesonintrospect: T.List[str]
    version: str

    def __post_init__(self) -> None:
        self.targets: T.List[TargetInstallData] = []
        self.headers: T.List[InstallDataBase] = []
        self.man: T.List[InstallDataBase] = []
        self.emptydir: T.List[InstallEmptyDir] = []
        self.data: T.List[InstallDataBase] = []
        self.symlinks: T.List[InstallSymlinkData] = []
        self.install_scripts: T.List[ExecutableSerialisation] = []
        self.install_subdirs: T.List[SubdirInstallData] = []

@dataclass(eq=False)
class TargetInstallData:
    fname: str
    outdir: str
    outdir_name: InitVar[T.Optional[str]]
    strip: bool
    install_name_mappings: T.Mapping[str, str]
    rpath_dirs_to_remove: T.Set[bytes]
    install_rpath: str
    # TODO: install_mode should just always be a FileMode object
    install_mode: T.Optional['FileMode']
    subproject: str
    optional: bool = False
    tag: T.Optional[str] = None
    can_strip: bool = False

    def __post_init__(self, outdir_name: T.Optional[str]) -> None:
        if outdir_name is None:
            outdir_name = os.path.join('{prefix}', self.outdir)
        self.out_name = os.path.join(outdir_name, os.path.basename(self.fname))

@dataclass(eq=False)
class InstallEmptyDir:
    path: str
    install_mode: 'FileMode'
    subproject: str
    tag: T.Optional[str] = None

@dataclass(eq=False)
class InstallDataBase:
    path: str
    install_path: str
    install_path_name: str
    install_mode: 'FileMode'
    subproject: str
    tag: T.Optional[str] = None
    data_type: T.Optional[str] = None
    follow_symlinks: T.Optional[bool] = None

@dataclass(eq=False)
class InstallSymlinkData:
    target: str
    name: str
    install_path: str
    subproject: str
    tag: T.Optional[str] = None
    allow_missing: bool = False

# cannot use dataclass here because "exclude" is out of order
class SubdirInstallData(InstallDataBase):
    def __init__(self, path: str, install_path: str, install_path_name: str,
                 install_mode: 'FileMode', exclude: T.Tuple[T.Set[str], T.Set[str]],
                 subproject: str, tag: T.Optional[str] = None, data_type: T.Optional[str] = None,
                 follow_symlinks: T.Optional[bool] = None):
        super().__init__(path, install_path, install_path_name, install_mode, subproject, tag, data_type, follow_symlinks)
        self.exclude = exclude

@dataclass(eq=False)
class TestSerialisation:
    name: str
    project_name: str
    suite: T.List[str]
    fname: T.List[str]
    is_cross_built: bool
    exe_wrapper: T.Optional[programs.ExternalProgram]
    needs_exe_wrapper: bool
    is_parallel: bool
    cmd_args: T.List[str]
    env: mesonlib.EnvironmentVariables
    should_fail: bool
    timeout: T.Optional[int]
    workdir: T.Optional[str]
    extra_paths: T.List[str]
    protocol: TestProtocol
    priority: int
    cmd_is_built: bool
    cmd_is_exe: bool
    depends: T.List[str]
    version: str
    verbose: bool

    def __post_init__(self) -> None:
        if self.exe_wrapper is not None:
            assert isinstance(self.exe_wrapper, programs.ExternalProgram)

def get_backend_from_name(backend: str, build: T.Optional[build.Build] = None, interpreter: T.Optional['Interpreter'] = None) -> T.Optional['Backend']:
    if backend == 'ninja':
        from . import ninjabackend
        return ninjabackend.NinjaBackend(build, interpreter)
    elif backend == 'vs':
        from . import vs2010backend
        return vs2010backend.autodetect_vs_version(build, interpreter)
    elif backend == 'vs2010':
        from . import vs2010backend
        return vs2010backend.Vs2010Backend(build, interpreter)
    elif backend == 'vs2012':
        from . import vs2012backend
        return vs2012backend.Vs2012Backend(build, interpreter)
    elif backend == 'vs2013':
        from . import vs2013backend
        return vs2013backend.Vs2013Backend(build, interpreter)
    elif backend == 'vs2015':
        from . import vs2015backend
        return vs2015backend.Vs2015Backend(build, interpreter)
    elif backend == 'vs2017':
        from . import vs2017backend
        return vs2017backend.Vs2017Backend(build, interpreter)
    elif backend == 'vs2019':
        from . import vs2019backend
        return vs2019backend.Vs2019Backend(build, interpreter)
    elif backend == 'vs2022':
        from . import vs2022backend
        return vs2022backend.Vs2022Backend(build, interpreter)
    elif backend == 'xcode':
        from . import xcodebackend
        return xcodebackend.XCodeBackend(build, interpreter)
    elif backend == 'none':
        from . import nonebackend
        return nonebackend.NoneBackend(build, interpreter)
    return None

def get_genvslite_backend(genvsname: str, build: T.Optional[build.Build] = None, interpreter: T.Optional['Interpreter'] = None) -> T.Optional['Backend']:
    if genvsname == 'vs2022':
        from . import vs2022backend
        return vs2022backend.Vs2022Backend(build, interpreter, gen_lite = True)
    return None

# This class contains the basic functionality that is needed by all backends.
# Feel free to move stuff in and out of it as you see fit.
class Backend:

    environment: T.Optional['Environment']
    name = '<UNKNOWN>'

    def __init__(self, build: T.Optional[build.Build], interpreter: T.Optional['Interpreter']):
        # Make it possible to construct a dummy backend
        # This is used for introspection without a build directory
        if build is None:
            self.environment = None
            return
        self.build = build
        self.interpreter = interpreter
        self.environment = build.environment
        self.processed_targets: T.Set[str] = set()
        self.build_dir = self.environment.get_build_dir()
        self.source_dir = self.environment.get_source_dir()
        self.build_to_src = mesonlib.relpath(self.environment.get_source_dir(),
                                             self.environment.get_build_dir())
        self.src_to_build = mesonlib.relpath(self.environment.get_build_dir(),
                                             self.environment.get_source_dir())

    # If requested via 'capture = True', returns captured compile args per
    # target (e.g. captured_args[target]) that can be used later, for example,
    # to populate things like intellisense fields in generated visual studio
    # projects (as is the case when using '--genvslite').
    #
    # 'vslite_ctx' is only provided when
    # we expect this backend setup/generation to make use of previously captured
    # compile args (as is the case when using '--genvslite').
    def generate(self, capture: bool = False, vslite_ctx: dict = None) -> T.Optional[dict]:
        raise RuntimeError(f'generate is not implemented in {type(self).__name__}')

    def get_target_filename(self, t: T.Union[build.Target, build.CustomTargetIndex], *, warn_multi_output: bool = True) -> str:
        if isinstance(t, build.CustomTarget):
            if warn_multi_output and len(t.get_outputs()) != 1:
                mlog.warning(f'custom_target {t.name!r} has more than one output! '
                             f'Using the first one. Consider using `{t.name}[0]`.')
            filename = t.get_outputs()[0]
        elif isinstance(t, build.CustomTargetIndex):
            filename = t.get_outputs()[0]
        else:
            assert isinstance(t, build.BuildTarget), t
            filename = t.get_filename()
        return os.path.join(self.get_target_dir(t), filename)

    def get_target_filename_abs(self, target: T.Union[build.Target, build.CustomTargetIndex]) -> str:
        return os.path.join(self.environment.get_build_dir(), self.get_target_filename(target))

    def get_target_debug_filename(self, target: build.BuildTarget) -> T.Optional[str]:
        assert isinstance(target, build.BuildTarget), target
        if target.get_debug_filename():
            debug_filename = target.get_debug_filename()
            return os.path.join(self.get_target_dir(target), debug_filename)
        else:
            return None

    def get_target_debug_filename_abs(self, target: build.BuildTarget) -> T.Optional[str]:
        assert isinstance(target, build.BuildTarget), target
        if not target.get_debug_filename():
            return None
        return os.path.join(self.environment.get_build_dir(), self.get_target_debug_filename(target))

    def get_source_dir_include_args(self, target: build.BuildTarget, compiler: 'Compiler', *, absolute_path: bool = False) -> T.List[str]:
        curdir = target.get_source_subdir()
        if absolute_path:
            lead = self.source_dir
        else:
            lead = self.build_to_src
        tmppath = os.path.normpath(os.path.join(lead, curdir))
        return compiler.get_include_args(tmppath, False)

    def get_build_dir_include_args(self, target: build.BuildTarget, compiler: 'Compiler', *, absolute_path: bool = False) -> T.List[str]:
        if absolute_path:
            curdir = os.path.join(self.build_dir, target.get_output_subdir())
        else:
            curdir = target.get_output_subdir()
            if curdir == '':
                curdir = '.'
        return compiler.get_include_args(curdir, False)

    def get_target_filename_for_linking(self, target: T.Union[build.Target, build.CustomTargetIndex]) -> T.Optional[str]:
        # On some platforms (msvc for instance), the file that is used for
        # dynamic linking is not the same as the dynamic library itself. This
        # file is called an import library, and we want to link against that.
        # On all other platforms, we link to the library directly.
        if isinstance(target, build.SharedLibrary):
            link_lib = target.get_import_filename() or target.get_filename()
            # In AIX, if we archive .so, the blibpath must link to archived shared library otherwise to the .so file.
            if mesonlib.is_aix() and target.aix_so_archive:
                link_lib = re.sub('[.][a]([.]?([0-9]+))*([.]?([a-z]+))*', '.a', link_lib.replace('.so', '.a'))
            return Path(self.get_target_dir(target), link_lib).as_posix()
        elif isinstance(target, build.StaticLibrary):
            return Path(self.get_target_dir(target), target.get_filename()).as_posix()
        elif isinstance(target, (build.CustomTarget, build.CustomTargetIndex)):
            if not target.is_linkable_target():
                raise MesonException(f'Tried to link against custom target "{target.name}", which is not linkable.')
            return Path(self.get_target_dir(target), target.get_filename()).as_posix()
        elif isinstance(target, build.Executable):
            if target.import_filename:
                return Path(self.get_target_dir(target), target.get_import_filename()).as_posix()
            else:
                return None
        raise AssertionError(f'BUG: Tried to link to {target!r} which is not linkable')

    @lru_cache(maxsize=None)
    def get_target_dir(self, target: T.Union[build.Target, build.CustomTargetIndex]) -> str:
        if isinstance(target, build.RunTarget):
            # this produces no output, only a dummy top-level name
            dirname = ''
        elif self.environment.coredata.get_option(OptionKey('layout')) == 'mirror':
            dirname = target.get_output_subdir()
        else:
            dirname = 'meson-out'
        return dirname

    def get_target_dir_relative_to(self, t: build.Target, o: build.Target) -> str:
        '''Get a target dir relative to another target's directory'''
        target_dir = os.path.join(self.environment.get_build_dir(), self.get_target_dir(t))
        othert_dir = os.path.join(self.environment.get_build_dir(), self.get_target_dir(o))
        return os.path.relpath(target_dir, othert_dir)

    def get_target_source_dir(self, target: build.Target) -> str:
        # if target dir is empty, avoid extraneous trailing / from os.path.join()
        target_dir = self.get_target_dir(target)
        if target_dir:
            return os.path.join(self.build_to_src, target_dir)
        return self.build_to_src

    def get_target_private_dir(self, target: T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex]) -> str:
        return os.path.join(self.get_target_filename(target, warn_multi_output=False) + '.p')

    def get_target_private_dir_abs(self, target: T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex]) -> str:
        return os.path.join(self.environment.get_build_dir(), self.get_target_private_dir(target))

    @lru_cache(maxsize=None)
    def get_target_generated_dir(
            self, target: T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex],
            gensrc: T.Union[build.CustomTarget, build.CustomTargetIndex, build.GeneratedList],
            src: str) -> str:
        """
        Takes a BuildTarget, a generator source (CustomTarget or GeneratedList),
        and a generated source filename.
        Returns the full path of the generated source relative to the build root
        """
        # CustomTarget generators output to the build dir of the CustomTarget
        if isinstance(gensrc, (build.CustomTarget, build.CustomTargetIndex)):
            return os.path.join(self.get_target_dir(gensrc), src)
        # GeneratedList generators output to the private build directory of the
        # target that the GeneratedList is used in
        return os.path.join(self.get_target_private_dir(target), src)

    def get_unity_source_file(self, target: T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex],
                              suffix: str, number: int) -> mesonlib.File:
        # There is a potential conflict here, but it is unlikely that
        # anyone both enables unity builds and has a file called foo-unity.cpp.
        osrc = f'{target.name}-unity{number}.{suffix}'
        return mesonlib.File.from_built_file(self.get_target_private_dir(target), osrc)

    def generate_unity_files(self, target: build.BuildTarget, unity_src: str) -> T.List[mesonlib.File]:
        abs_files: T.List[str] = []
        result: T.List[mesonlib.File] = []
        compsrcs = classify_unity_sources(target.compilers.values(), unity_src)
        unity_size = target.get_option(OptionKey('unity_size'))
        assert isinstance(unity_size, int), 'for mypy'

        def init_language_file(suffix: str, unity_file_number: int) -> T.TextIO:
            unity_src = self.get_unity_source_file(target, suffix, unity_file_number)
            outfileabs = unity_src.absolute_path(self.environment.get_source_dir(),
                                                 self.environment.get_build_dir())
            outfileabs_tmp = outfileabs + '.tmp'
            abs_files.append(outfileabs)
            outfileabs_tmp_dir = os.path.dirname(outfileabs_tmp)
            if not os.path.exists(outfileabs_tmp_dir):
                os.makedirs(outfileabs_tmp_dir)
            result.append(unity_src)
            return open(outfileabs_tmp, 'w', encoding='utf-8')

        # For each language, generate unity source files and return the list
        for comp, srcs in compsrcs.items():
            files_in_current = unity_size + 1
            unity_file_number = 0
            # TODO: this could be simplified with an algorithm that pre-sorts
            # the sources into the size of chunks we want
            ofile = None
            for src in srcs:
                if files_in_current >= unity_size:
                    if ofile:
                        ofile.close()
                    ofile = init_language_file(comp.get_default_suffix(), unity_file_number)
                    unity_file_number += 1
                    files_in_current = 0
                ofile.write(f'#include<{src}>\n')
                files_in_current += 1
            if ofile:
                ofile.close()

        for x in abs_files:
            mesonlib.replace_if_different(x, x + '.tmp')
        return result

    @staticmethod
    def relpath(todir: str, fromdir: str) -> str:
        return os.path.relpath(os.path.join('dummyprefixdir', todir),
                               os.path.join('dummyprefixdir', fromdir))

    def flatten_object_list(self, target: build.BuildTarget, proj_dir_to_build_root: str = ''
                            ) -> T.Tuple[T.List[str], T.List[build.BuildTargetTypes]]:
        obj_list, deps = self._flatten_object_list(target, target.get_objects(), proj_dir_to_build_root)
        return list(dict.fromkeys(obj_list)), deps

    def determine_ext_objs(self, objects: build.ExtractedObjects, proj_dir_to_build_root: str = '') -> T.List[str]:
        obj_list, _ = self._flatten_object_list(objects.target, [objects], proj_dir_to_build_root)
        return list(dict.fromkeys(obj_list))

    def _flatten_object_list(self, target: build.BuildTarget,
                             objects: T.Sequence[T.Union[str, 'File', build.ExtractedObjects]],
                             proj_dir_to_build_root: str) -> T.Tuple[T.List[str], T.List[build.BuildTargetTypes]]:
        obj_list: T.List[str] = []
        deps: T.List[build.BuildTargetTypes] = []
        for obj in objects:
            if isinstance(obj, str):
                o = os.path.join(proj_dir_to_build_root,
                                 self.build_to_src, target.get_source_subdir(), obj)
                obj_list.append(o)
            elif isinstance(obj, mesonlib.File):
                if obj.is_built:
                    o = os.path.join(proj_dir_to_build_root,
                                     obj.rel_to_builddir(self.build_to_src))
                    obj_list.append(o)
                else:
                    o = os.path.join(proj_dir_to_build_root,
                                     self.build_to_src)
                    obj_list.append(obj.rel_to_builddir(o))
            elif isinstance(obj, build.ExtractedObjects):
                if obj.recursive:
                    objs, d = self._flatten_object_list(obj.target, obj.objlist, proj_dir_to_build_root)
                    obj_list.extend(objs)
                    deps.extend(d)
                obj_list.extend(self._determine_ext_objs(obj, proj_dir_to_build_root))
                deps.append(obj.target)
            else:
                raise MesonException('Unknown data type in object list.')
        return obj_list, deps

    @staticmethod
    def is_swift_target(target: build.BuildTarget) -> bool:
        for s in target.sources:
            if isinstance(s, (str, File)) and s.endswith('swift'):
                return True
        return False

    def determine_swift_dep_dirs(self, target: build.BuildTarget) -> T.List[str]:
        result: T.List[str] = []
        for l in target.link_targets:
            result.append(self.get_target_private_dir_abs(l))
        return result

    def get_executable_serialisation(
            self, cmd: T.Sequence[T.Union[programs.ExternalProgram, build.BuildTarget, build.CustomTarget, File, str]],
            workdir: T.Optional[str] = None,
            extra_bdeps: T.Optional[T.List[build.BuildTarget]] = None,
            capture: T.Optional[str] = None,
            feed: T.Optional[str] = None,
            env: T.Optional[mesonlib.EnvironmentVariables] = None,
            tag: T.Optional[str] = None,
            verbose: bool = False,
            installdir_map: T.Optional[T.Dict[str, str]] = None) -> 'ExecutableSerialisation':

        # XXX: cmd_args either need to be lowered to strings, or need to be checked for non-string arguments, right?
        exe, *raw_cmd_args = cmd
        if isinstance(exe, programs.ExternalProgram):
            exe_cmd = exe.get_command()
            exe_for_machine = exe.for_machine
        elif isinstance(exe, build.BuildTarget):
            exe_cmd = [self.get_target_filename_abs(exe)]
            exe_for_machine = exe.for_machine
        elif isinstance(exe, build.CustomTarget):
            # The output of a custom target can either be directly runnable
            # or not, that is, a script, a native binary or a cross compiled
            # binary when exe wrapper is available and when it is not.
            # This implementation is not exhaustive but it works in the
            # common cases.
            exe_cmd = [self.get_target_filename_abs(exe)]
            exe_for_machine = MachineChoice.BUILD
        elif isinstance(exe, mesonlib.File):
            exe_cmd = [exe.rel_to_builddir(self.environment.source_dir)]
            exe_for_machine = MachineChoice.BUILD
        else:
            exe_cmd = [exe]
            exe_for_machine = MachineChoice.BUILD

        cmd_args: T.List[str] = []
        for c in raw_cmd_args:
            if isinstance(c, programs.ExternalProgram):
                p = c.get_path()
                assert isinstance(p, str)
                cmd_args.append(p)
            elif isinstance(c, (build.BuildTarget, build.CustomTarget)):
                cmd_args.append(self.get_target_filename_abs(c))
            elif isinstance(c, mesonlib.File):
                cmd_args.append(c.rel_to_builddir(self.environment.source_dir))
            else:
                cmd_args.append(c)

        machine = self.environment.machines[exe_for_machine]
        if machine.is_windows() or machine.is_cygwin():
            extra_paths = self.determine_windows_extra_paths(exe, extra_bdeps or [])
        else:
            extra_paths = []

        if self.environment.need_exe_wrapper(exe_for_machine):
            if not self.environment.has_exe_wrapper():
                msg = 'An exe_wrapper is needed but was not found. Please define one ' \
                      'in cross file and check the command and/or add it to PATH.'
                raise MesonException(msg)
            exe_wrapper = self.environment.get_exe_wrapper()
        else:
            if exe_cmd[0].endswith('.jar'):
                exe_cmd = ['java', '-jar'] + exe_cmd
            elif exe_cmd[0].endswith('.exe') and not (mesonlib.is_windows() or mesonlib.is_cygwin() or mesonlib.is_wsl()):
                exe_cmd = ['mono'] + exe_cmd
            exe_wrapper = None

        workdir = workdir or self.environment.get_build_dir()
        return ExecutableSerialisation(exe_cmd + cmd_args, env,
                                       exe_wrapper, workdir,
                                       extra_paths, capture, feed, tag, verbose, installd
### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/backend/backends.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2016 The Meson development team

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, InitVar
from functools import lru_cache
from itertools import chain
from pathlib import Path
import copy
import enum
import json
import os
import pickle
import re
import shlex
import shutil
import typing as T
import hashlib

from .. import build
from .. import dependencies
from .. import programs
from .. import mesonlib
from .. import mlog
from ..compilers import LANGUAGES_USING_LDFLAGS, detect
from ..mesonlib import (
    File, MachineChoice, MesonException, OrderedSet,
    ExecutableSerialisation, classify_unity_sources, OptionKey
)

if T.TYPE_CHECKING:
    from .._typing import ImmutableListProtocol
    from ..arglist import CompilerArgs
    from ..compilers import Compiler
    from ..environment import Environment
    from ..interpreter import Interpreter, Test
    from ..linkers.linkers import StaticLinker
    from ..mesonlib import FileMode, FileOrString

    from typing_extensions import TypedDict

    _ALL_SOURCES_TYPE = T.List[T.Union[File, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList]]

    class TargetIntrospectionData(TypedDict):

        language: str
        compiler: T.List[str]
        parameters: T.List[str]
        sources: T.List[str]
        generated_sources: T.List[str]


# Languages that can mix with C or C++ but don't support unity builds yet
# because the syntax we use for unity builds is specific to C/++/ObjC/++.
# Assembly files cannot be unitified and neither can LLVM IR files
LANGS_CANT_UNITY = ('d', 'fortran', 'vala')

@dataclass(eq=False)
class RegenInfo:
    source_dir: str
    build_dir: str
    depfiles: T.List[str]

class TestProtocol(enum.Enum):

    EXITCODE = 0
    TAP = 1
    GTEST = 2
    RUST = 3

    @classmethod
    def from_str(cls, string: str) -> 'TestProtocol':
        if string == 'exitcode':
            return cls.EXITCODE
        elif string == 'tap':
            return cls.TAP
        elif string == 'gtest':
            return cls.GTEST
        elif string == 'rust':
            return cls.RUST
        raise MesonException(f'unknown test format {string}')

    def __str__(self) -> str:
        cls = type(self)
        if self is cls.EXITCODE:
            return 'exitcode'
        elif self is cls.GTEST:
            return 'gtest'
        elif self is cls.RUST:
            return 'rust'
        return 'tap'


@dataclass(eq=False)
class CleanTrees:
    '''
    Directories outputted by custom targets that have to be manually cleaned
    because on Linux `ninja clean` only deletes empty directories.
    '''
    build_dir: str
    trees: T.List[str]

@dataclass(eq=False)
class InstallData:
    source_dir: str
    build_dir: str
    prefix: str
    libdir: str
    strip_bin: T.List[str]
    # TODO: in python 3.8 or with typing_Extensions this could be:
    # `T.Union[T.Literal['preserve'], int]`, which would be more accurate.
    install_umask: T.Union[str, int]
    mesonintrospect: T.List[str]
    version: str

    def __post_init__(self) -> None:
        self.targets: T.List[TargetInstallData] = []
        self.headers: T.List[InstallDataBase] = []
        self.man: T.List[InstallDataBase] = []
        self.emptydir: T.List[InstallEmptyDir] = []
        self.data: T.List[InstallDataBase] = []
        self.symlinks: T.List[InstallSymlinkData] = []
        self.install_scripts: T.List[ExecutableSerialisation] = []
        self.install_subdirs: T.List[SubdirInstallData] = []

@dataclass(eq=False)
class TargetInstallData:
    fname: str
    outdir: str
    outdir_name: InitVar[T.Optional[str]]
    strip: bool
    install_name_mappings: T.Mapping[str, str]
    rpath_dirs_to_remove: T.Set[bytes]
    install_rpath: str
    # TODO: install_mode should just always be a FileMode object
    install_mode: T.Optional['FileMode']
    subproject: str
    optional: bool = False
    tag: T.Optional[str] = None
    can_strip: bool = False

    def __post_init__(self, outdir_name: T.Optional[str]) -> None:
        if outdir_name is None:
            outdir_name = os.path.join('{prefix}', self.outdir)
        self.out_name = os.path.join(outdir_name, os.path.basename(self.fname))

@dataclass(eq=False)
class InstallEmptyDir:
    path: str
    install_mode: 'FileMode'
    subproject: str
    tag: T.Optional[str] = None

@dataclass(eq=False)
class InstallDataBase:
    path: str
    install_path: str
    install_path_name: str
    install_mode: 'FileMode'
    subproject: str
    tag: T.Optional[str] = None
    data_type: T.Optional[str] = None
    follow_symlinks: T.Optional[bool] = None

@dataclass(eq=False)
class InstallSymlinkData:
    target: str
    name: str
    install_path: str
    subproject: str
    tag: T.Optional[str] = None
    allow_missing: bool = False

# cannot use dataclass here because "exclude" is out of order
class SubdirInstallData(InstallDataBase):
    def __init__(self, path: str, install_path: str, install_path_name: str,
                 install_mode: 'FileMode', exclude: T.Tuple[T.Set[str], T.Set[str]],
                 subproject: str, tag: T.Optional[str] = None, data_type: T.Optional[str] = None,
                 follow_symlinks: T.Optional[bool] = None):
        super().__init__(path, install_path, install_path_name, install_mode, subproject, tag, data_type, follow_symlinks)
        self.exclude = exclude


@dataclass(eq=False)
class TestSerialisation:
    name: str
    project_name: str
    suite: T.List[str]
    fname: T.List[str]
    is_cross_built: bool
    exe_wrapper: T.Optional[programs.ExternalProgram]
    needs_exe_wrapper: bool
    is_parallel: bool
    cmd_args: T.List[str]
    env: mesonlib.EnvironmentVariables
    should_fail: bool
    timeout: T.Optional[int]
    workdir: T.Optional[str]
    extra_paths: T.List[str]
    protocol: TestProtocol
    priority: int
    cmd_is_built: bool
    cmd_is_exe: bool
    depends: T.List[str]
    version: str
    verbose: bool

    def __post_init__(self) -> None:
        if self.exe_wrapper is not None:
            assert isinstance(self.exe_wrapper, programs.ExternalProgram)


def get_backend_from_name(backend: str, build: T.Optional[build.Build] = None, interpreter: T.Optional['Interpreter'] = None) -> T.Optional['Backend']:
    if backend == 'ninja':
        from . import ninjabackend
        return ninjabackend.NinjaBackend(build, interpreter)
    elif backend == 'vs':
        from . import vs2010backend
        return vs2010backend.autodetect_vs_version(build, interpreter)
    elif backend == 'vs2010':
        from . import vs2010backend
        return vs2010backend.Vs2010Backend(build, interpreter)
    elif backend == 'vs2012':
        from . import vs2012backend
        return vs2012backend.Vs2012Backend(build, interpreter)
    elif backend == 'vs2013':
        from . import vs2013backend
        return vs2013backend.Vs2013Backend(build, interpreter)
    elif backend == 'vs2015':
        from . import vs2015backend
        return vs2015backend.Vs2015Backend(build, interpreter)
    elif backend == 'vs2017':
        from . import vs2017backend
        return vs2017backend.Vs2017Backend(build, interpreter)
    elif backend == 'vs2019':
        from . import vs2019backend
        return vs2019backend.Vs2019Backend(build, interpreter)
    elif backend == 'vs2022':
        from . import vs2022backend
        return vs2022backend.Vs2022Backend(build, interpreter)
    elif backend == 'xcode':
        from . import xcodebackend
        return xcodebackend.XCodeBackend(build, interpreter)
    elif backend == 'none':
        from . import nonebackend
        return nonebackend.NoneBackend(build, interpreter)
    return None


def get_genvslite_backend(genvsname: str, build: T.Optional[build.Build] = None, interpreter: T.Optional['Interpreter'] = None) -> T.Optional['Backend']:
    if genvsname == 'vs2022':
        from . import vs2022backend
        return vs2022backend.Vs2022Backend(build, interpreter, gen_lite = True)
    return None

# This class contains the basic functionality that is needed by all backends.
# Feel free to move stuff in and out of it as you see fit.
class Backend:

    environment: T.Optional['Environment']
    name = '<UNKNOWN>'

    def __init__(self, build: T.Optional[build.Build], interpreter: T.Optional['Interpreter']):
        # Make it possible to construct a dummy backend
        # This is used for introspection without a build directory
        if build is None:
            self.environment = None
            return
        self.build = build
        self.interpreter = interpreter
        self.environment = build.environment
        self.processed_targets: T.Set[str] = set()
        self.build_dir = self.environment.get_build_dir()
        self.source_dir = self.environment.get_source_dir()
        self.build_to_src = mesonlib.relpath(self.environment.get_source_dir(),
                                             self.environment.get_build_dir())
        self.src_to_build = mesonlib.relpath(self.environment.get_build_dir(),
                                             self.environment.get_source_dir())

    # If requested via 'capture = True', returns captured compile args per
    # target (e.g. captured_args[target]) that can be used later, for example,
    # to populate things like intellisense fields in generated visual studio
    # projects (as is the case when using '--genvslite').
    #
    # 'vslite_ctx' is only provided when
    # we expect this backend setup/generation to make use of previously captured
    # compile args (as is the case when using '--genvslite').
    def generate(self, capture: bool = False, vslite_ctx: dict = None) -> T.Optional[dict]:
        raise RuntimeError(f'generate is not implemented in {type(self).__name__}')

    def get_target_filename(self, t: T.Union[build.Target, build.CustomTargetIndex], *, warn_multi_output: bool = True) -> str:
        if isinstance(t, build.CustomTarget):
            if warn_multi_output and len(t.get_outputs()) != 1:
                mlog.warning(f'custom_target {t.name!r} has more than one output! '
                             f'Using the first one. Consider using `{t.name}[0]`.')
            filename = t.get_outputs()[0]
        elif isinstance(t, build.CustomTargetIndex):
            filename = t.get_outputs()[0]
        else:
            assert isinstance(t, build.BuildTarget), t
            filename = t.get_filename()
        return os.path.join(self.get_target_dir(t), filename)

    def get_target_filename_abs(self, target: T.Union[build.Target, build.CustomTargetIndex]) -> str:
        return os.path.join(self.environment.get_build_dir(), self.get_target_filename(target))

    def get_target_debug_filename(self, target: build.BuildTarget) -> T.Optional[str]:
        assert isinstance(target, build.BuildTarget), target
        if target.get_debug_filename():
            debug_filename = target.get_debug_filename()
            return os.path.join(self.get_target_dir(target), debug_filename)
        else:
            return None

    def get_target_debug_filename_abs(self, target: build.BuildTarget) -> T.Optional[str]:
        assert isinstance(target, build.BuildTarget), target
        if not target.get_debug_filename():
            return None
        return os.path.join(self.environment.get_build_dir(), self.get_target_debug_filename(target))

    def get_source_dir_include_args(self, target: build.BuildTarget, compiler: 'Compiler', *, absolute_path: bool = False) -> T.List[str]:
        curdir = target.get_source_subdir()
        if absolute_path:
            lead = self.source_dir
        else:
            lead = self.build_to_src
        tmppath = os.path.normpath(os.path.join(lead, curdir))
        return compiler.get_include_args(tmppath, False)

    def get_build_dir_include_args(self, target: build.BuildTarget, compiler: 'Compiler', *, absolute_path: bool = False) -> T.List[str]:
        if absolute_path:
            curdir = os.path.join(self.build_dir, target.get_output_subdir())
        else:
            curdir = target.get_output_subdir()
            if curdir == '':
                curdir = '.'
        return compiler.get_include_args(curdir, False)

    def get_target_filename_for_linking(self, target: T.Union[build.Target, build.CustomTargetIndex]) -> T.Optional[str]:
        # On some platforms (msvc for instance), the file that is used for
        # dynamic linking is not the same as the dynamic library itself. This
        # file is called an import library, and we want to link against that.
        # On all other platforms, we link to the library directly.
        if isinstance(target, build.SharedLibrary):
            link_lib = target.get_import_filename() or target.get_filename()
            # In AIX, if we archive .so, the blibpath must link to archived shared library otherwise to the .so file.
            if mesonlib.is_aix() and target.aix_so_archive:
                link_lib = re.sub('[.][a]([.]?([0-9]+))*([.]?([a-z]+))*', '.a', link_lib.replace('.so', '.a'))
            return Path(self.get_target_dir(target), link_lib).as_posix()
        elif isinstance(target, build.StaticLibrary):
            return Path(self.get_target_dir(target), target.get_filename()).as_posix()
        elif isinstance(target, (build.CustomTarget, build.CustomTargetIndex)):
            if not target.is_linkable_target():
                raise MesonException(f'Tried to link against custom target "{target.name}", which is not linkable.')
            return Path(self.get_target_dir(target), target.get_filename()).as_posix()
        elif isinstance(target, build.Executable):
            if target.import_filename:
                return Path(self.get_target_dir(target), target.get_import_filename()).as_posix()
            else:
                return None
        raise AssertionError(f'BUG: Tried to link to {target!r} which is not linkable')

    @lru_cache(maxsize=None)
    def get_target_dir(self, target: T.Union[build.Target, build.CustomTargetIndex]) -> str:
        if isinstance(target, build.RunTarget):
            # this produces no output, only a dummy top-level name
            dirname = ''
        elif self.environment.coredata.get_option(OptionKey('layout')) == 'mirror':
            dirname = target.get_output_subdir()
        else:
            dirname = 'meson-out'
        return dirname

    def get_target_dir_relative_to(self, t: build.Target, o: build.Target) -> str:
        '''Get a target dir relative to another target's directory'''
        target_dir = os.path.join(self.environment.get_build_dir(), self.get_target_dir(t))
        othert_dir = os.path.join(self.environment.get_build_dir(), self.get_target_dir(o))
        return os.path.relpath(target_dir, othert_dir)

    def get_target_source_dir(self, target: build.Target) -> str:
        # if target dir is empty, avoid extraneous trailing / from os.path.join()
        target_dir = self.get_target_dir(target)
        if target_dir:
            return os.path.join(self.build_to_src, target_dir)
        return self.build_to_src

    def get_target_private_dir(self, target: T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex]) -> str:
        return os.path.join(self.get_target_filename(target, warn_multi_output=False) + '.p')

    def get_target_private_dir_abs(self, target: T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex]) -> str:
        return os.path.join(self.environment.get_build_dir(), self.get_target_private_dir(target))

    @lru_cache(maxsize=None)
    def get_target_generated_dir(
            self, target: T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex],
            gensrc: T.Union[build.CustomTarget, build.CustomTargetIndex, build.GeneratedList],
            src: str) -> str:
        """
        Takes a BuildTarget, a generator source (CustomTarget or GeneratedList),
        and a generated source filename.
        Returns the full path of the generated source relative to the build root
        """
        # CustomTarget generators output to the build dir of the CustomTarget
        if isinstance(gensrc, (build.CustomTarget, build.CustomTargetIndex)):
            return os.path.join(self.get_target_dir(gensrc), src)
        # GeneratedList generators output to the private build directory of the
        # target that the GeneratedList is used in
        return os.path.join(self.get_target_private_dir(target), src)

    def get_unity_source_file(self, target: T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex],
                              suffix: str, number: int) -> mesonlib.File:
        # There is a potential conflict here, but it is unlikely that
        # anyone both enables unity builds and has a file called foo-unity.cpp.
        osrc = f'{target.name}-unity{number}.{suffix}'
        return mesonlib.File.from_built_file(self.get_target_private_dir(target), osrc)

    def generate_unity_files(self, target: build.BuildTarget, unity_src: str) -> T.List[mesonlib.File]:
        abs_files: T.List[str] = []
        result: T.List[mesonlib.File] = []
        compsrcs = classify_unity_sources(target.compilers.values(), unity_src)
        unity_size = target.get_option(OptionKey('unity_size'))
        assert isinstance(unity_size, int), 'for mypy'

        def init_language_file(suffix: str, unity_file_number: int) -> T.TextIO:
            unity_src = self.get_unity_source_file(target, suffix, unity_file_number)
            outfileabs = unity_src.absolute_path(self.environment.get_source_dir(),
                                                 self.environment.get_build_dir())
            outfileabs_tmp = outfileabs + '.tmp'
            abs_files.append(outfileabs)
            outfileabs_tmp_dir = os.path.dirname(outfileabs_tmp)
            if not os.path.exists(outfileabs_tmp_dir):
                os.makedirs(outfileabs_tmp_dir)
            result.append(unity_src)
            return open(outfileabs_tmp, 'w', encoding='utf-8')

        # For each language, generate unity source files and return the list
        for comp, srcs in compsrcs.items():
            files_in_current = unity_size + 1
            unity_file_number = 0
            # TODO: this could be simplified with an algorithm that pre-sorts
            # the sources into the size of chunks we want
            ofile = None
            for src in srcs:
                if files_in_current >= unity_size:
                    if ofile:
                        ofile.close()
                    ofile = init_language_file(comp.get_default_suffix(), unity_file_number)
                    unity_file_number += 1
                    files_in_current = 0
                ofile.write(f'#include<{src}>\n')
                files_in_current += 1
            if ofile:
                ofile.close()

        for x in abs_files:
            mesonlib.replace_if_different(x, x + '.tmp')
        return result

    @staticmethod
    def relpath(todir: str, fromdir: str) -> str:
        return os.path.relpath(os.path.join('dummyprefixdir', todir),
                               os.path.join('dummyprefixdir', fromdir))

    def flatten_object_list(self, target: build.BuildTarget, proj_dir_to_build_root: str = ''
                            ) -> T.Tuple[T.List[str], T.List[build.BuildTargetTypes]]:
        obj_list, deps = self._flatten_object_list(target, target.get_objects(), proj_dir_to_build_root)
        return list(dict.fromkeys(obj_list)), deps

    def determine_ext_objs(self, objects: build.ExtractedObjects, proj_dir_to_build_root: str = '') -> T.List[str]:
        obj_list, _ = self._flatten_object_list(objects.target, [objects], proj_dir_to_build_root)
        return list(dict.fromkeys(obj_list))

    def _flatten_object_list(self, target: build.BuildTarget,
                             objects: T.Sequence[T.Union[str, 'File', build.ExtractedObjects]],
                             proj_dir_to_build_root: str) -> T.Tuple[T.List[str], T.List[build.BuildTargetTypes]]:
        obj_list: T.List[str] = []
        deps: T.List[build.BuildTargetTypes] = []
        for obj in objects:
            if isinstance(obj, str):
                o = os.path.join(proj_dir_to_build_root,
                                 self.build_to_src, target.get_source_subdir(), obj)
                obj_list.append(o)
            elif isinstance(obj, mesonlib.File):
                if obj.is_built:
                    o = os.path.join(proj_dir_to_build_root,
                                     obj.rel_to_builddir(self.build_to_src))
                    obj_list.append(o)
                else:
                    o = os.path.join(proj_dir_to_build_root,
                                     self.build_to_src)
                    obj_list.append(obj.rel_to_builddir(o))
            elif isinstance(obj, build.ExtractedObjects):
                if obj.recursive:
                    objs, d = self._flatten_object_list(obj.target, obj.objlist, proj_dir_to_build_root)
                    obj_list.extend(objs)
                    deps.extend(d)
                obj_list.extend(self._determine_ext_objs(obj, proj_dir_to_build_root))
                deps.append(obj.target)
            else:
                raise MesonException('Unknown data type in object list.')
        return obj_list, deps

    @staticmethod
    def is_swift_target(target: build.BuildTarget) -> bool:
        for s in target.sources:
            if isinstance(s, (str, File)) and s.endswith('swift'):
                return True
        return False

    def determine_swift_dep_dirs(self, target: build.BuildTarget) -> T.List[str]:
        result: T.List[str] = []
        for l in target.link_targets:
            result.append(self.get_target_private_dir_abs(l))
        return result

    def get_executable_serialisation(
            self, cmd: T.Sequence[T.Union[programs.ExternalProgram, build.BuildTarget, build.CustomTarget, File, str]],
            workdir: T.Optional[str] = None,
            extra_bdeps: T.Optional[T.List[build.BuildTarget]] = None,
            capture: T.Optional[str] = None,
            feed: T.Optional[str] = None,
            env: T.Optional[mesonlib.EnvironmentVariables] = None,
            tag: T.Optional[str] = None,
            verbose: bool = False,
            installdir_map: T.Optional[T.Dict[str, str]] = None) -> 'ExecutableSerialisation':

        # XXX: cmd_args either need to be lowered to strings, or need to be checked for non-string arguments, right?
        exe, *raw_cmd_args = cmd
        if isinstance(exe, programs.ExternalProgram):
            exe_cmd = exe.get_command()
            exe_for_machine = exe.for_machine
        elif isinstance(exe, build.BuildTarget):
            exe_cmd = [self.get_target_filename_abs(exe)]
            exe_for_machine = exe.for_machine
        elif isinstance(exe, build.CustomTarget):
            # The output of a custom target can either be directly runnable
            # or not, that is, a script, a native binary or a cross compiled
            # binary when exe wrapper is available and when it is not.
            # This implementation is not exhaustive but it works in the
            # common cases.
            exe_cmd = [self.get_target_filename_abs(exe)]
            exe_for_machine = MachineChoice.BUILD
        elif isinstance(exe, mesonlib.File):
            exe_cmd = [exe.rel_to_builddir(self.environment.source_dir)]
            exe_for_machine = MachineChoice.BUILD
        else:
            exe_cmd = [exe]
            exe_for_machine = MachineChoice.BUILD

        cmd_args: T.List[str] = []
        for c in raw_cmd_args:
            if isinstance(c, programs.ExternalProgram):
                p = c.get_path()
                assert isinstance(p, str)
                cmd_args.append(p)
            elif isinstance(c, (build.BuildTarget, build.CustomTarget)):
                cmd_args.append(self.get_target_filename_abs(c))
            elif isinstance(c, mesonlib.File):
                cmd_args.append(c.rel_to_builddir(self.environment.source_dir))
            else:
                cmd_args.append(c)

        machine = self.environment.machines[exe_for_machine]
        if machine.is_windows() or machine.is_cygwin():
            extra_paths = self.determine_windows_extra_paths(exe, extra_bdeps or [])
        else:
            extra_paths = []

        if self.environment.need_exe_wrapper(exe_for_machine):
            if not self.environment.has_exe_wrapper():
                msg = 'An exe_wrapper is needed but was not found. Please define one ' \
                      'in cross file and check the command and/or add it to PATH.'
                raise MesonException(msg)
            exe_wrapper = self.environment.get_exe_wrapper()
        else:
            if exe_cmd[0].endswith('.jar'):
                exe_cmd = ['java', '-jar'] + exe_cmd
            elif exe_cmd[0].endswith('.exe') and not (mesonlib.is_windows() or mesonlib.is_cygwin() or mesonlib.is_wsl()):
                exe_cmd = ['mono'] + exe_cmd
            exe_wrapper = None

        workdir = workdir or self.environment.get_build_dir()
        return ExecutableSerialisation(exe_cmd + cmd_args, env,
                                       exe_wrapper, workdir,
                                       extra_paths, capture, feed, tag, verbose, installdir_map)

    def as_meson_exe_cmdline(self, exe: T.Union[str, mesonlib.File, build.BuildTarget, build.CustomTarget, programs.ExternalProgram],
                             cmd_args: T.Sequence[T.Union[str, mesonlib.File, build.BuildTarget, build.CustomTarget, programs.ExternalProgram]],
                             workdir: T.Optional[str] = None,
                             extra_bdeps: T.Optional[T.List[build.BuildTarget]] = None,
                             capture: T.Optional[str] = None,
                             feed: T.Optional[str] = None,
                             force_serialize: bool = False,
                             env: T.Optional[mesonlib.EnvironmentVariables] = None,
                             verbose: bool = False) -> T.Tuple[T.Sequence[T.Union[str, File, build.Target, programs.ExternalProgram]], str]:
        '''
        Serialize an executable for running with a generator or a custom target
        '''
        cmd: T.List[T.Union[str, mesonlib.File, build.BuildTarget, build.CustomTarget, programs.ExternalProgram]] = []
        cmd.append(exe)
        cmd.extend(cmd_args)
        es = self.get_executable_serialisation(cmd, workdir, extra_bdeps, capture, feed, env, verbose=verbose)
        reasons: T.List[str] = []
        if es.extra_paths:
            reasons.append('to set PATH')

        if es.exe_wrapper:
            reasons.append('to use exe_wrapper')

        if workdir:
            reasons.append('to set workdir')

        if any('\n' in c for c in es.cmd_args):
            reasons.append('because command contains newlines')

        if env and env.varnames:
            reasons.append('to set env')

        # force_serialize passed to this function means that the VS backend has
        # decided it absolutely cannot use real commands. This is "always",
        # because it's not clear what will work (other than compilers) and so
        # we don't bother to handle a variety of common cases that probably do
        # work.
        #
        # It's also overridden for a few conditions that can't be handled
        # inside a command line

        can_use_env = not force_serialize
        force_serialize = force_serialize or bool(reasons)

        if capture:
            reasons.append('to capture output')
        if feed:
            reasons.append('to feed input')

        if can_use_env and reasons == ['to set env'] and shutil.which('env'):
            envlist = []
            for k, v in env.get_env({}).items():
                envlist.append(f'{k}={v}')
            return ['env'] + envlist + es.cmd_args, ', '.join(reasons)

        if not force_serialize:
            if not capture and not feed:
                return es.cmd_args, ''
            args: T.List[str] = []
            if capture:
                args += ['--capture', capture]
            if feed:
                args += ['--feed', feed]

            return (
                self.environment.get_build_command() + ['--internal', 'exe'] + args + ['--'] + es.cmd_args,
                ', '.join(reasons)
            )

        if isinstance(exe, (programs.ExternalProgram,
                            build.BuildTarget, build.CustomTarget)):
            basename = os.path.basename(exe.name)
        elif isinstance(exe, mesonlib.File):
            basename = os.path.basename(exe.fname)
        else:
            basename = os.path.basename(exe)

        # Can't just use exe.name here; it will likely be run more than once
        # Take a digest of the cmd args, env, workdir, capture, and feed. This
        # avoids collisions and also makes the name deterministic over
        # regenerations which avoids a rebuild by Ninja because the cmdline
        # stays the same.
        hasher = hashlib.sha1()
        if es.env:
            es.env.hash(hasher)
        hasher.update(bytes(str(es.cmd_args), encoding='utf-8'))
        hasher.update(bytes(str(es.workdir), encoding='utf-8'))
        hasher.update(bytes(str(capture), encoding='utf-8'))
        hasher.update(bytes(str(feed), encoding='utf-8'))
        digest = hasher.hexdigest()
        scratch_file = f'meson_exe_{basename}_{digest}.dat'
        exe_data = os.path.join(self.environment.get_scratch_dir(), scratch_file)
        with open(exe_data, 'wb') as f:
            pickle.dump(es, f)
        return (self.environment.get_build_command() + ['--internal', 'exe', '--unpickle', exe_data],
                ', '.join(reasons))

    def serialize_tests(self) -> T.Tuple[str, str]:
        test_data = os.path.join(self.environment.get_scratch_dir(), 'meson_test_setup.dat')
        with open(test_data, 'wb') as datafile:
            self.write_test_file(datafile)
        benchmark_data = os.path.join(self.environment.get_scratch_dir(), 'meson_benchmark_setup.dat')
        with open(benchmark_data, 'wb') as datafile:
            self.write_benchmark_file(datafile)
        return test_data, benchmark_data

    def determine_linker_and_stdlib_args(self, target: build.BuildTarget) -> T.Tuple[T.Union['Compiler', 'StaticLinker'], T.List[str]]:
        '''
        If we're building a static library, there is only one static linker.
        Otherwise, we query the target for the dynamic linker.
        '''
        if isinstance(target, build.StaticLibrary):
            return self.build.static_linker[target.for_machine], []
        l, stdlib_args = target.get_clink_dynamic_linker_and_stdlibs()
        return l, stdlib_args

    @staticmethod
    def _libdir_is_system(libdir: str, compilers: T.Mapping[str, 'Compiler'], env: 'Environment') -> bool:
        libdir = os.path.normpath(libdir)
        for cc in compilers.values():
            if libdir in cc.get_library_dirs(env):
                return True
        return False

    def get_external_rpath_dirs(self, target: build.BuildTarget) -> T.Set[str]:
        args: T.List[str] = []
        for lang in LANGUAGES_USING_LDFLAGS:
            try:
                e = self.environment.coredata.get_external_link_args(target.for_machine, lang)
                if isinstance(e, str):
                    args.append(e)
                else:
                    args.extend(e)
            except Exception:
                pass
        return self.get_rpath_dirs_from_link_args(args)

    @staticmethod
    def get_rpath_dirs_from_link_args(args: T.List[str]) -> T.Set[str]:
        dirs: T.Set[str] = set()
        # Match rpath formats:
        # -Wl,-rpath=
        # -Wl,-rpath,
        rpath_regex = re.compile(r'-Wl,-rpath[=,]([^,]+)')
        # Match solaris style compat runpath formats:
        # -Wl,-R
        # -Wl,-R,
        runpath_regex = re.compile(r'-Wl,-R[,]?([^,]+)')
        # Match symbols formats:
        # -Wl,--just-symbols=
        # -Wl,--just-symbols,
        symbols_regex = re.compile(r'-Wl,--just-symbols[=,]([^,]+)')
        for arg in args:
            rpath_match = rpath_regex.match(arg)
            if rpath_match:
                for dir in rpath_match.group(1).split(':'):
                    dirs.add(dir)
            runpath_match = runpath_regex.match(arg)
            if runpath_match:
                for dir in runpath_match.group(1).split(':'):
                    # The symbols arg is an rpath if the path is a directory
```