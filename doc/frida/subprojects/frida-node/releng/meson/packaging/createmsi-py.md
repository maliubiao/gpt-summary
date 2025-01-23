Response:
Let's break down the thought process for analyzing this Python script for MSI packaging.

**1. Initial Understanding of the Goal:**

The docstring clearly states the script's purpose: "generating MSI packages for Windows users."  This immediately tells us the context: Windows installers.

**2. Deconstructing the Script -  Key Components and Their Roles:**

I'll go through the code section by section, identifying the core functionalities:

* **Imports:** Standard Python libraries (subprocess, shutil, uuid, etc.) and a local module (`mesonbuild.coredata`). This hints at interaction with the system, file manipulation, unique ID generation, and potentially reading version information from another Meson component.
* **`WINVER_CHECK`:**  A string representing a Windows version check condition. The comment about `CDATA` suggests this will be embedded directly into the MSI's XML definition.
* **`gen_guid()`:**  A simple function to generate a UUID, crucial for MSI component identification.
* **`Node` Class:**  A data structure to hold directory and file information within a directory structure. This is likely used to represent the files to be packaged.
* **`PackageGenerator` Class:** This is the core of the script. I need to examine its methods:
    * `__init__`: Initializes various attributes like product name, version, GUIDs, file paths, and crucially, the `staging_dirs`. The hardcoded paths for Visual C++ redistributables are important to note. The `feature_properties` and `feature_components` dictionaries suggest how features (installable parts) will be structured in the MSI.
    * `build_dist()`:  Uses PyInstaller to bundle the Meson Python script into executables. This is a significant step in creating the distributable. The staging directories are used to organize the output. Deleting "info" directories is a specific workaround related to WiX filename restrictions.
    * `del_infodirs()`:  Helper function to remove directories with hyphens in their names.
    * `generate_files()`:  This is where the MSI XML (WXS) file is created using `xml.etree.ElementTree`. It defines the structure of the installer, including directories, files, features, and dependencies (like the Visual C++ runtime). The `create_xml` and `build_features` methods are called from here. The pretty-printing and CDATA insertion are final touches.
    * `build_features()`:  Adds feature elements to the MSI XML.
    * `create_xml()`: Recursively traverses the staging directories and creates the corresponding directory and file elements in the MSI XML. It assigns unique IDs to components and adds environment variable modifications.
    * `build_package()`:  Uses the `wix` toolchain (specifically `wix build`) to compile the generated WXS file into an MSI package.
* **`install_wix()`:**  Provides instructions for installing the WiX toolchain using `dotnet`.
* **`if __name__ == '__main__':`:**  The main execution block. It checks for the `meson.py` file, installs WiX if needed, upgrades PyInstaller, and then instantiates and calls the methods of the `PackageGenerator`.

**3. Identifying Connections to Reverse Engineering, Binary/Kernel Knowledge:**

* **MSI Structure:**  Understanding that MSIs have a specific internal structure, including tables and components, is relevant to reverse engineering installers. While this script *creates* the MSI, someone reverse-engineering it would analyze this structure.
* **Executable Packaging (PyInstaller):**  PyInstaller's function is to bundle Python code and its dependencies into a standalone executable. Reverse engineers often encounter applications packaged with tools like PyInstaller and need to understand how to extract the original code.
* **Visual C++ Redistributable:** The inclusion of the VC++ runtime highlights the dependency of the built executable on specific system libraries. Reverse engineers often need to identify and understand such dependencies.
* **Environment Variables:**  The script modifies the `PATH` environment variable. Understanding how environment variables work is crucial for both application functionality and reverse engineering (e.g., understanding where an application might be loading libraries from).

**4. Logical Reasoning and Assumptions:**

* **Input:** The script assumes the presence of `meson.py` in the current directory. It also assumes PyInstaller and the WiX toolchain are either installed or can be installed. The structure of the `staging_dirs` is implicitly defined by the `build_dist()` method.
* **Output:** The primary output is the `meson-{version}-64.msi` file, a Windows Installer package. The intermediate output is the `meson.wxs` XML file and the `meson.wixobj` object file.

**5. User/Programming Errors:**

* **Missing Dependencies:** The script explicitly checks for `pyinstaller` and `wix`. A common error would be not having these installed.
* **Incorrect Paths:** The hardcoded paths to the VC++ redistributables are a potential point of failure if the Visual Studio installation is in a different location.
* **Running in the Wrong Directory:** The script checks if `meson.py` exists in the current directory. Running it elsewhere would lead to an error.
* **WiX XML Errors:** If the generated `meson.wxs` file has syntax errors (though the script tries to avoid this), the `wix build` command will fail.

**6. Tracing User Actions:**

The most likely scenario is a developer working on the Frida project needing to create a Windows installer for a new release. The steps would be:

1. **Navigate to the `frida/subprojects/frida-node/releng/meson/packaging/` directory** in their development environment.
2. **Ensure they have the necessary prerequisites:** Python, PyInstaller, and the WiX toolchain (or the script will attempt to install WiX).
3. **Execute the script:** `python createmsi.py`.

**Self-Correction/Refinement During Analysis:**

* Initially, I might have just focused on the XML generation. However, realizing the role of `build_dist()` and PyInstaller is crucial to understanding the entire packaging process.
* The hardcoded paths for the VC++ redistributable seemed like a potential weakness. I made sure to highlight this as a potential point of failure or something to be aware of.
* I also considered the interaction with `mesonbuild.coredata`, recognizing that this likely fetches the version information, tying this script into the larger Meson build system.

By following this detailed, step-by-step thought process, I can systematically analyze the script and provide a comprehensive answer to the user's query.
这个Python脚本 `createmsi.py` 的主要功能是为 Frida Dynamic Instrumentation Tool 的 Node.js 绑定创建一个 **Windows Installer (MSI) 包**。  它使用 WiX toolset 来定义和构建 MSI 安装程序。

以下是该脚本的详细功能分解：

**核心功能：生成 MSI 安装包**

1. **定义 MSI 包的元数据:**
   - 产品名称 (`self.product_name`)
   - 制造商 (`self.manufacturer`)
   - 版本号 (`self.version`)，从 `mesonbuild.coredata` 中获取，并移除 "dev" 后缀。
   - 升级代码 (`self.update_guid`)，用于标识同一产品的不同版本。
   - 输出文件名 (`self.final_output`)

2. **构建待打包的文件结构 (通过 PyInstaller):**
   - 使用 PyInstaller 将 `meson.py` 打包成独立的 Windows 可执行文件 (`meson.exe`)。
   - 将 `ninja.exe` 复制到指定的目录。
   - 创建两个临时目录 (`self.staging_dirs`: 'dist', 'dist2') 来组织打包的文件。

3. **生成 WiX 描述文件 (meson.wxs):**
   - 使用 `xml.etree.ElementTree` 库创建一个 XML 文件 (`meson.wxs`)，该文件描述了 MSI 安装包的内容和结构。
   - 定义安装目录 (`INSTALLDIR`) 和程序文件目录 (`ProgramFiles64Folder`)。
   - 将打包好的 `meson.exe` 和 `ninja.exe` 文件添加到 MSI 包中。
   - 包含 Visual C++ 运行库合并模块 (`.msm`) 作为依赖项。
   - 定义安装界面和特性（Features）。
   - 添加环境变量修改 (将安装目录添加到 PATH 环境变量)。

4. **使用 WiX 工具链构建 MSI 包:**
   - 调用 `wix build` 命令，将生成的 `meson.wxs` 文件编译成 MSI 安装包 (`.msi`)。

**具体功能点：**

* **`gen_guid()`:**  生成唯一的 GUID (全局唯一标识符)，用于标识 MSI 包中的组件。
* **`Node` 类:**  一个简单的类，用于表示文件系统中的目录和文件，方便在生成 WiX XML 时进行组织。
* **`PackageGenerator` 类:** 封装了生成 MSI 包的所有逻辑。
    * **`__init__`:** 初始化各种参数和路径，包括查找 Visual C++ 运行库合并模块的路径。
    * **`build_dist()`:** 使用 PyInstaller 构建待打包的文件。
    * **`del_infodirs()`:**  删除 PyInstaller 生成的包含连字符的元数据目录，因为 WiX 不允许文件名中包含连字符。
    * **`generate_files()`:** 生成主要的 WiX XML 文件 (`meson.wxs`)。
    * **`build_features()`:** 在 WiX XML 中定义安装特性（Features）。
    * **`create_xml()`:** 递归遍历文件系统，生成 WiX XML 中表示目录和文件的元素。
    * **`build_package()`:** 调用 WiX 工具链构建 MSI 包。
* **`install_wix()`:** 提供安装 WiX 工具链的辅助方法，使用 `dotnet` 和 `nuget`。

**与逆向方法的关系：**

这个脚本本身不是一个逆向工具，而是 Frida 工具链的一部分，用于**分发** Frida 的 Node.js 绑定。 然而，理解 MSI 包的结构和安装过程对于逆向分析基于 MSI 安装的软件是至关重要的。

**举例说明:**

* **逆向工程师分析 MSI 包:**  逆向工程师可以使用工具（如 Orca MSI editor）打开 `meson-{version}-64.msi` 文件，查看其内部结构，包括包含的文件、注册表修改、环境变量设置等。这可以帮助他们了解软件的安装过程、依赖关系以及潜在的恶意行为。
* **分析 Frida 的安装行为:**  通过分析由该脚本生成的 MSI 包，逆向工程师可以了解 Frida 的 Node.js 绑定在 Windows 系统上的安装位置、依赖的 Visual C++ 运行库版本以及如何将其添加到 PATH 环境变量中，从而方便在命令行中调用。

**涉及的二进制底层、Linux、Android 内核及框架的知识：**

虽然此脚本专注于 Windows MSI 打包，但它最终是为了分发 Frida，而 Frida 本身深入到二进制底层和操作系统内核。

**举例说明:**

* **二进制可执行文件 (`meson.exe`, `ninja.exe`):**  PyInstaller 将 Python 脚本打包成 Windows 可执行文件，这些文件是二进制格式，由机器代码组成。理解可执行文件的结构 (PE 格式) 对于逆向分析至关重要。
* **Visual C++ 运行库 (`.msm`):**  MSI 包包含了 Visual C++ 运行库的合并模块。这意味着 Frida 的 Node.js 绑定依赖于这些底层的 C++ 库才能运行。理解这些库提供的功能对于理解 Frida 的依赖关系很重要。
* **PATH 环境变量:**  脚本修改了 Windows 的 PATH 环境变量。理解环境变量的作用以及如何在操作系统中查找和加载可执行文件是基本的操作系统知识。

**逻辑推理：**

**假设输入:**

* 脚本运行在包含 `meson.py` 文件的目录中。
* 系统已安装或可以安装 PyInstaller 和 WiX toolset。
* 能够找到匹配的 Visual C++ 运行库合并模块。

**预期输出:**

* 在当前目录下生成一个名为 `meson-{version}-64.msi` 的 Windows 安装包。
* 该 MSI 包能够将 `meson.exe` 和 `ninja.exe` 安装到 "Program Files" 目录下的 "Meson" 文件夹中。
* 安装过程中会将安装目录添加到系统的 PATH 环境变量中。
* 如果未安装必要的 Visual C++ 运行库，安装程序会包含这些库。

**用户或编程常见的使用错误：**

* **缺少依赖工具:** 如果用户在没有安装 PyInstaller 或 WiX toolset 的情况下运行脚本，会报错。脚本会尝试使用 `install_wix()` 安装 WiX，但如果 `dotnet` 环境有问题，安装可能会失败。
* **找不到 Visual C++ 运行库:** 脚本中硬编码了查找 Visual C++ 运行库合并模块的路径。如果用户的 Visual Studio 安装在非标准位置，脚本可能找不到对应的 `.msm` 文件，导致打包失败。
* **在错误的目录下运行脚本:** 如果不在包含 `meson.py` 的目录下运行脚本，会报错提示找不到 `meson.py` 文件。
* **WiX 工具链配置问题:**  如果 WiX 工具链没有正确安装或配置（例如，缺少必要的扩展），构建 MSI 包的步骤可能会失败。
* **PyInstaller 构建失败:** 如果 `meson.py` 文件存在错误，PyInstaller 构建可执行文件的步骤可能会失败。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **开发者修改了 Frida 的 Node.js 绑定代码。**
2. **开发者需要创建一个新的 Windows 安装包来发布更新。**
3. **开发者导航到 Frida 项目的源代码目录： `frida/subprojects/frida-node/releng/meson/packaging/`。**
4. **开发者执行该脚本： `python createmsi.py`。**

如果脚本执行过程中出现错误，开发者可以根据错误信息进行调试：

* **如果提示找不到 `meson.py`:** 检查是否在正确的目录下运行脚本。
* **如果提示找不到 `pyinstaller` 或 `wix`:** 检查是否已安装这些工具，或者检查 `install_wix()` 函数的执行情况。
* **如果提示找不到 Visual C++ 运行库:** 检查 Visual Studio 的安装路径，或者修改脚本中查找 `.msm` 文件的路径。
* **如果 `wix build` 命令报错:** 查看 WiX 工具链的错误信息，检查 `meson.wxs` 文件的语法是否正确。这通常需要对 WiX 的 XML 结构有一定的了解。
* **如果安装后的程序运行有问题:**  可以检查 MSI 包安装的文件、注册表项和环境变量是否符合预期，例如使用 Orca MSI editor 或 Windows 的注册表编辑器。

总而言之，`createmsi.py` 是 Frida 项目中一个重要的构建脚本，它负责将 Frida 的 Node.js 绑定打包成用户友好的 Windows 安装程序。理解其功能和背后的技术，对于 Frida 的开发者、用户以及逆向分析相关人员都有重要的意义。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/packaging/createmsi.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2017-2021 The Meson development team

'''
This script is for generating MSI packages
for Windows users.
'''

import subprocess
import shutil
import uuid
import sys
import os
from glob import glob
import xml.etree.ElementTree as ET

sys.path.append(os.getcwd())
from mesonbuild import coredata

# Elementtree does not support CDATA. So hack it.
WINVER_CHECK = 'Installed OR (VersionNT64 &gt; 602)>'

def gen_guid():
    '''
       Generate guid
    '''
    return str(uuid.uuid4()).upper()

class Node:
    '''
       Node to hold path and directory values
    '''

    def __init__(self, dirs, files):
        self.check_dirs(dirs)
        self.check_files(files)
        self.dirs = dirs
        self.files = files

    @staticmethod
    def check_dirs(dirs):
        '''
           Check to see if directory is instance of list
        '''
        assert isinstance(dirs, list)

    @staticmethod
    def check_files(files):
        '''
           Check to see if files is instance of list
        '''
        assert isinstance(files, list)


class PackageGenerator:
    '''
       Package generator for MSI packages
    '''

    def __init__(self):
        self.product_name = 'Meson Build System'
        self.manufacturer = 'The Meson Development Team'
        self.version = coredata.version.replace('dev', '')
        self.root = None
        self.guid = '*'
        self.update_guid = '141527EE-E28A-4D14-97A4-92E6075D28B2'
        self.main_xml = 'meson.wxs'
        self.main_o = 'meson.wixobj'
        self.final_output = f'meson-{self.version}-64.msi'
        self.staging_dirs = ['dist', 'dist2']
        self.progfile_dir = 'ProgramFiles64Folder'
        redist_globs = ['C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\VC\\Redist\\MSVC\\v*\\MergeModules\\Microsoft_VC142_CRT_x64.msm',
                        'C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Redist\\MSVC\\v*\\MergeModules\\Microsoft_VC143_CRT_x64.msm']
        redist_path = None
        for g in redist_globs:
            trials = glob(g)
            if len(trials) > 1:
                sys.exit('MSM glob matched multiple entries:' + '\n'.join(trials))
            if len(trials) == 1:
                redist_path = trials[0]
                break
        if redist_path is None:
            sys.exit('No MSMs found.')
        self.redist_path = redist_path
        self.component_num = 0
        self.feature_properties = {
            self.staging_dirs[0]: {
                'Id': 'MainProgram',
                'Title': 'Meson',
                'Description': 'Meson executables',
                'Level': '1',
                'AllowAbsent': 'no',
            },
            self.staging_dirs[1]: {
                'Id': 'NinjaProgram',
                'Title': 'Ninja',
                'Description': 'Ninja build tool',
                'Level': '1',
            }
        }
        self.feature_components = {}
        for s_d in self.staging_dirs:
            self.feature_components[s_d] = []

    def build_dist(self):
        '''
           Build dist file from PyInstaller info
        '''
        for sdir in self.staging_dirs:
            if os.path.exists(sdir):
                shutil.rmtree(sdir)
        main_stage, ninja_stage = self.staging_dirs

        pyinstaller = shutil.which('pyinstaller')
        if not pyinstaller:
            print("ERROR: This script requires pyinstaller.")
            sys.exit(1)

        pyinstaller_tmpdir = 'pyinst-tmp'
        if os.path.exists(pyinstaller_tmpdir):
            shutil.rmtree(pyinstaller_tmpdir)
        pyinst_cmd = [pyinstaller,
                      '--clean',
                      '--additional-hooks-dir=packaging',
                      '--distpath',
                      pyinstaller_tmpdir]
        pyinst_cmd += ['meson.py']
        subprocess.check_call(pyinst_cmd)
        shutil.move(pyinstaller_tmpdir + '/meson', main_stage)
        self.del_infodirs(main_stage)
        if not os.path.exists(os.path.join(main_stage, 'meson.exe')):
            sys.exit('Meson exe missing from staging dir.')
        os.mkdir(ninja_stage)
        shutil.copy(shutil.which('ninja'), ninja_stage)
        if not os.path.exists(os.path.join(ninja_stage, 'ninja.exe')):
            sys.exit('Ninja exe missing from staging dir.')

    def del_infodirs(self, dirname):
        # Starting with 3.9.something there are some
        # extra metadatadirs that have a hyphen in their
        # file names. This is a forbidden character in WiX
        # filenames so delete them.
        for d in glob(os.path.join(dirname, '*-info')):
            shutil.rmtree(d)

    def generate_files(self):
        '''
           Generate package files for MSI installer package
        '''
        self.root = ET.Element('Wix', {
            'xmlns': 'http://wixtoolset.org/schemas/v4/wxs',
            'xmlns:ui': 'http://wixtoolset.org/schemas/v4/wxs/ui'
        })

        package = ET.SubElement(self.root, 'Package', {
            'Name': self.product_name,
            'Manufacturer': 'The Meson Development Team',
            'UpgradeCode': self.update_guid,
            'Language': '1033',
            'Codepage':  '1252',
            'Version': self.version,
        })

        ET.SubElement(package, 'SummaryInformation', {
            'Keywords': 'Installer',
            'Description': f'Meson {self.version} installer',
            'Manufacturer': 'The Meson Development Team',
        })

        ET.SubElement(package,
                      'Launch',
                      {'Message': 'This application is only supported on Windows 10 or higher.',
                       'Condition': 'X'*len(WINVER_CHECK)})

        ET.SubElement(package, 'MajorUpgrade',
                      {'DowngradeErrorMessage':
                       'A newer version of Meson is already installed.'})

        ET.SubElement(package, 'Media', {
            'Id': '1',
            'Cabinet': 'meson.cab',
            'EmbedCab': 'yes',
        })
        targetdir = ET.SubElement(package, 'StandardDirectory', {
            'Id': 'ProgramFiles64Folder',
        })
        installdir = ET.SubElement(targetdir, 'Directory', {
            'Id': 'INSTALLDIR',
            'Name': 'Meson',
        })
        ET.SubElement(installdir, 'Merge', {
            'Id': 'VCRedist',
            'SourceFile': self.redist_path,
            'DiskId': '1',
            'Language': '0',
        })

        ET.SubElement(package, 'ui:WixUI', {
            'Id': 'WixUI_FeatureTree',
        })
        for s_d in self.staging_dirs:
            assert os.path.isdir(s_d)
        top_feature = ET.SubElement(package, 'Feature', {
            'Id': 'Complete',
            'Title': 'Meson ' + self.version,
            'Description': 'The complete package',
            'Display': 'expand',
            'Level': '1',
            'ConfigurableDirectory': 'INSTALLDIR',
        })
        for s_d in self.staging_dirs:
            nodes = {}
            for root, dirs, files in os.walk(s_d):
                cur_node = Node(dirs, files)
                nodes[root] = cur_node
            self.create_xml(nodes, s_d, installdir, s_d)
            self.build_features(top_feature, s_d)
        vcredist_feature = ET.SubElement(top_feature, 'Feature', {
            'Id': 'VCRedist',
            'Title': 'Visual C++ runtime',
            'AllowAdvertise': 'no',
            'Display': 'hidden',
            'Level': '1',
        })
        ET.SubElement(vcredist_feature, 'MergeRef', {'Id': 'VCRedist'})
        ET.ElementTree(self.root).write(self.main_xml, encoding='utf-8', xml_declaration=True)
        # ElementTree cannot do pretty-printing, so do it manually
        import xml.dom.minidom
        doc = xml.dom.minidom.parse(self.main_xml)
        with open(self.main_xml, 'w') as open_file:
            open_file.write(doc.toprettyxml())
        # One last fix, add CDATA.
        with open(self.main_xml) as open_file:
            data = open_file.read()
        data = data.replace('X'*len(WINVER_CHECK), WINVER_CHECK)
        with open(self.main_xml, 'w') as open_file:
            open_file.write(data)

    def build_features(self, top_feature, staging_dir):
        '''
           Generate build features
        '''
        feature = ET.SubElement(top_feature, 'Feature', self.feature_properties[staging_dir])
        for component_id in self.feature_components[staging_dir]:
            ET.SubElement(feature, 'ComponentRef', {
                'Id': component_id,
            })

    def create_xml(self, nodes, current_dir, parent_xml_node, staging_dir):
        '''
           Create XML file
        '''
        cur_node = nodes[current_dir]
        if cur_node.files:
            component_id = f'ApplicationFiles{self.component_num}'
            comp_xml_node = ET.SubElement(parent_xml_node, 'Component', {
                'Id': component_id,
                'Bitness': 'always64',
                'Guid': gen_guid(),
            })
            self.feature_components[staging_dir].append(component_id)
            if self.component_num == 0:
                ET.SubElement(comp_xml_node, 'Environment', {
                    'Id': 'Environment',
                    'Name': 'PATH',
                    'Part': 'last',
                    'System': 'yes',
                    'Action': 'set',
                    'Value': '[INSTALLDIR]',
                })
            self.component_num += 1
            for f_node in cur_node.files:
                file_id = os.path.join(current_dir, f_node).replace('\\', '_').replace('#', '_').replace('-', '_')
                ET.SubElement(comp_xml_node, 'File', {
                    'Id': file_id,
                    'Name': f_node,
                    'Source': os.path.join(current_dir, f_node),
                })

        for dirname in cur_node.dirs:
            dir_id = os.path.join(current_dir, dirname).replace('\\', '_').replace('/', '_').replace('-', '_')
            dir_node = ET.SubElement(parent_xml_node, 'Directory', {
                'Id': dir_id,
                'Name': dirname,
            })
            self.create_xml(nodes, os.path.join(current_dir, dirname), dir_node, staging_dir)

    def build_package(self):
        '''
           Generate the Meson build MSI package.
        '''
        subprocess.check_call(['wix',
                               'build',
                               '-bindvariable', 'WixUILicenseRtf=packaging\\License.rtf',
                               '-ext', 'WixToolset.UI.wixext',
                               '-culture', 'en-us',
                               '-arch', 'x64',
                               '-o',
                               self.final_output,
                               self.main_xml,
                               ])


def install_wix():
    subprocess.check_call(['dotnet',
                           'nuget',
                           'add',
                           'source',
                           'https://api.nuget.org/v3/index.json'])
    subprocess.check_call(['dotnet',
                           'tool',
                           'install',
                           '--global',
                           'wix'])
    subprocess.check_call(['wix',
                           'extension',
                           'add',
                           'WixToolset.UI.wixext',
                           ])

if __name__ == '__main__':
    if not os.path.exists('meson.py'):
        sys.exit(print('Run me in the top level source dir.'))
    if not shutil.which('wix'):
        install_wix()
    subprocess.check_call(['pip', 'install', '--upgrade', 'pyinstaller'])

    p = PackageGenerator()
    p.build_dist()
    p.generate_files()
    p.build_package()
```