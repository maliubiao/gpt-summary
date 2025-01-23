Response:
Let's break down the thought process for analyzing this Python script.

**1. Initial Understanding - The Big Picture:**

The first step is to read the docstring at the top. It clearly states the purpose: generating MSI packages for Windows for the Frida dynamic instrumentation tool. This immediately tells us the script is related to software distribution and is Windows-specific.

**2. Functionality Breakdown -  Reading the Code Sequentially:**

Now, we need to go through the code block by block. For each class and function, ask "What is this doing?".

* **Imports:**  Standard library imports like `subprocess`, `shutil`, `uuid`, `os`, `glob`, `xml.etree.ElementTree` give clues about what tasks are being performed (running external commands, file manipulation, generating unique IDs, OS interactions, file pattern matching, and XML processing). The custom import `mesonbuild.coredata` suggests it's interacting with the Meson build system's internal data.

* **`gen_guid()`:** Simple function, clearly generates a UUID.

* **`Node` Class:** Represents a directory with its subdirectories and files. Basic data structure.

* **`PackageGenerator` Class:** This is the core of the script. Its `__init__` method sets up important properties like product name, version, paths, and crucially, finds the Visual C++ redistributable merge module (`.msm`). The `build_dist()` method uses PyInstaller to package the Python script into executables. `generate_files()` creates the WiX XML configuration file. `build_features()` adds features to the XML. `create_xml()` recursively generates the directory structure and file entries in the XML. `build_package()` calls the WiX toolchain to create the MSI.

* **`install_wix()`:**  Handles installing the WiX toolchain if it's not present.

* **`if __name__ == '__main__':`:** The main entry point. Checks for dependencies (meson.py, WiX), upgrades PyInstaller, and then instantiates `PackageGenerator` to execute the build process.

**3. Identifying Connections to Reverse Engineering:**

Now, with a general understanding, the next step is to actively look for connections to reverse engineering concepts.

* **MSI Packages:** MSI packages are the standard installation format on Windows. Reverse engineers often encounter them when analyzing software. Understanding how they are built (like with this script) provides valuable context.

* **`fridaDynamic instrumentation tool`:** The script's context is explicitly related to Frida. This is the strongest link. Frida *is* a reverse engineering tool. The MSI package being created is for distributing Frida.

* **Packaging Executables:** The script uses PyInstaller to create standalone executables. Reverse engineers often analyze these packaged executables. Understanding the packaging process can sometimes reveal insights.

* **Visual C++ Redistributable:**  The script includes the VC++ runtime. This is common for Windows applications. Reverse engineers need to be aware of these dependencies.

**4. Identifying Connections to Low-Level/Kernel/Framework Concepts:**

Look for code elements that touch on these areas:

* **Windows Specifics:**  The script uses `ProgramFiles64Folder`, `.msi` extension, WiX toolchain, and refers to Windows versions (Windows 10 or higher). This clearly indicates Windows low-level knowledge.

* **Binary Executables:** The script packages `meson.exe` and `ninja.exe`. These are binary executables.

* **Environment Variables (PATH):** The script modifies the `PATH` environment variable during installation. This is a fundamental OS concept.

* **No Direct Kernel/Framework Interaction:**  While the *result* of this script is an installer for a dynamic instrumentation tool that *can* interact with kernels and frameworks, the *script itself* doesn't directly manipulate those. It's about packaging.

**5. Logical Reasoning and Hypothetical Inputs/Outputs:**

Think about what the script does with data.

* **Input:**  The core input is the `meson.py` script and potentially the `ninja` executable. The script also relies on the presence of the VC++ redistributable.
* **Processing:**  The script transforms these inputs into an MSI package by creating an XML configuration, packaging the executables, and using the WiX toolchain.
* **Output:**  The main output is the `meson-<version>-64.msi` file.

**6. Common User Errors:**

Consider points where a user might make mistakes:

* **Missing Dependencies:**  Not having PyInstaller or the WiX toolchain installed.
* **Incorrect Paths:** The script relies on finding the VC++ redistributable at specific paths. If these paths are wrong, the build will fail.
* **Running in the Wrong Directory:** The script explicitly checks if `meson.py` exists in the current directory.

**7. Debugging Steps (How to Arrive at This Script):**

Imagine a developer is debugging an issue with the Frida Windows installer.

* **Problem:** Users report installation problems on Windows.
* **Investigation:** The developer would look at the installer creation process.
* **Source Code:** They would find the script responsible for generating the MSI package. The file path `frida/releng/meson/packaging/createmsi.py` provides a clear indication of its purpose and location within the Frida project.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This script just packages files."  **Correction:**  It *does* package files, but it also generates the MSI structure using WiX, handles dependencies like the VC++ runtime, and modifies environment variables.
* **Initial thought:** "This directly interacts with the Windows kernel." **Correction:** While Frida can, *this script* focuses on the packaging and distribution aspects. It prepares the installer, which then installs Frida, which can interact with the kernel. The script is a step removed from direct kernel interaction.

By following these steps, we can systematically analyze the script and extract the requested information. The key is to move from a high-level understanding to detailed code analysis, while actively looking for connections to the specified concepts (reverse engineering, low-level details, etc.).
好的，我们来详细分析一下 `frida/releng/meson/packaging/createmsi.py` 这个脚本的功能及其与你提到领域的关联。

**脚本功能概览:**

这个 Python 脚本的主要功能是**为 Frida 这个动态 instrumentation 工具生成 Windows 平台上的 MSI (Microsoft Installer) 安装包**。 它使用 WiX Toolset 这个开源工具集来创建 MSI 包。

更具体地说，脚本执行以下步骤：

1. **配置信息:**  定义了 MSI 包的各种属性，如产品名称、制造商、版本号、升级代码等。这些信息会被嵌入到生成的 MSI 文件中。
2. **构建分发目录 (`dist`, `dist2`):**  使用 PyInstaller 将 Frida 的 Python 源代码 (`meson.py`) 打包成 Windows 可执行文件 (`meson.exe`)，并将其放置在指定的临时目录中。同时，也会将 Ninja 构建工具的可执行文件 (`ninja.exe`) 复制到另一个临时目录。
3. **查找 Visual C++ Redistributable:**  查找系统中已安装的 Visual C++ 运行库合并模块 (`.msm` 文件)。这是因为 Frida 依赖于这些运行库。
4. **生成 WiX 描述文件 (`meson.wxs`):**  这是一个 XML 文件，用于描述 MSI 包的内容、结构、安装行为等。脚本会动态生成这个文件，包括：
    * 定义安装目录结构 (`ProgramFiles64Folder` -> `Meson`)。
    * 将 Frida 的可执行文件和 Ninja 的可执行文件添加到不同的“Feature”中，允许用户在安装时选择安装哪些组件。
    * 包含 Visual C++ Redistributable 的合并模块。
    * 设置环境变量 (`PATH`)，以便在安装后可以直接运行 `meson` 命令。
5. **使用 WiX 编译生成 MSI 包 (`meson-<version>-64.msi`):**  调用 WiX 工具链 (`wix`, `build`)，将生成的 WiX 描述文件 (`meson.wxs`) 编译成最终的 MSI 安装包。

**与逆向方法的关联及举例:**

* **目标软件分析的准备:**  MSI 安装包是 Windows 软件发布的标准形式。逆向工程师经常需要分析目标软件的安装过程，以了解其文件结构、注册表修改、依赖项等信息。`createmsi.py` 这个脚本展示了 Frida 自身的打包过程，可以帮助逆向工程师理解 Frida 的安装方式，从而更好地进行 Frida 自身的逆向分析或者理解 Frida 如何与目标进程交互。例如，通过分析生成的 `meson.wxs` 文件，可以清楚地看到 Frida 的可执行文件被安装在哪里，环境变量如何被设置，这对于后续使用 Frida 进行动态分析至关重要。

* **动态链接库 (DLL) 依赖:**  脚本中包含了对 Visual C++ Redistributable 的处理。逆向分析经常涉及到理解软件的依赖关系，特别是动态链接库的依赖。这个脚本展示了 Frida 如何打包其运行所需的 C++ 运行时库，这在逆向分析任何依赖这些运行库的软件时都是一个重要的知识点。

* **了解软件的组成部分:**  脚本将 Frida 和 Ninja 分别放入不同的 "Feature" 中。这反映了 Frida 工具链的组成部分。逆向工程师在分析复杂软件时，需要将其拆解成不同的模块来理解。这个脚本提供了一个很好的例子，说明一个工具是如何组织其不同组件的。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

* **二进制可执行文件打包 (`meson.exe`, `ninja.exe`):**  脚本使用 PyInstaller 将 Python 脚本打包成 Windows 可执行文件。虽然脚本本身是用 Python 编写的，但最终生成的是二进制可执行文件。这涉及到将 Python 字节码、依赖库以及 Python 解释器打包成单个可执行文件的过程，理解这个过程涉及到对操作系统加载可执行文件的机制的了解。

* **环境变量 (`PATH`):**  脚本在 MSI 安装过程中设置了 `PATH` 环境变量。这是一个操作系统级别的概念，允许用户在命令行中直接运行可执行文件而无需指定完整路径。理解环境变量对于理解软件的运行环境至关重要。

* **Visual C++ Redistributable:**  虽然脚本运行在 Windows 上，但它处理的 Visual C++ Redistributable 是用 C++ 编写的，编译成二进制代码。这涉及到对不同编程语言编译产物的理解。

**需要注意的是，虽然 Frida *本身* 是一个跨平台的动态 instrumentation 工具，可以用于分析 Linux 和 Android 上的进程，但这个 *特定的脚本* `createmsi.py` 的作用域仅限于生成 Windows 平台上的安装包。它本身并不直接涉及 Linux 或 Android 内核及框架的知识。**  它只是将 Frida 工具打包成 Windows 可以安装的形式。

**逻辑推理及假设输入与输出:**

假设输入：

1. Frida 的 Python 源代码 `meson.py` 存在于当前目录。
2. Ninja 构建工具的可执行文件 `ninja.exe` 存在于系统的 PATH 环境变量中。
3. 用户的 Windows 系统上安装了 Visual Studio 2019 或 2022，并且相应的 Visual C++ Redistributable 合并模块存在于预定义的路径中。
4. 系统中安装了 PyInstaller 和 WiX Toolset。

输出：

*   在当前目录下生成一个名为 `meson-<版本号>-64.msi` 的 MSI 安装包文件。
*   在 `dist` 目录下包含打包好的 `meson.exe` 文件。
*   在 `dist2` 目录下包含 `ninja.exe` 文件。
*   生成一个名为 `meson.wxs` 的 WiX 描述文件。

**用户或编程常见的使用错误及举例:**

* **缺少依赖工具:**  如果用户在运行此脚本之前没有安装 PyInstaller 或 WiX Toolset，脚本会报错并退出。 例如，如果未安装 WiX，脚本会尝试使用 `dotnet tool install --global wix` 来安装，但如果用户的网络有问题或者 `dotnet` 环境配置不正确，安装可能会失败。

* **找不到 Visual C++ Redistributable:**  脚本中硬编码了 Visual C++ Redistributable 合并模块的查找路径。如果用户安装的 Visual Studio 版本或配置不同，脚本可能找不到所需的 `.msm` 文件，导致打包失败并提示 "No MSMs found."。

* **在错误的目录下运行脚本:** 脚本开头会检查当前目录下是否存在 `meson.py` 文件。如果用户在错误的目录下运行脚本，会收到 "Run me in the top level source dir." 的错误提示。

* **PyInstaller 打包失败:**  如果 `meson.py` 代码有错误或者 PyInstaller 的配置有问题，打包过程可能会失败，导致 `dist` 目录下缺少 `meson.exe` 文件，脚本会检查这个情况并报错 "Meson exe missing from staging dir."。

**用户操作是如何一步步的到达这里，作为调试线索:**

通常，用户不会直接运行这个 `createmsi.py` 脚本。 这个脚本是 Frida 开发团队在发布 Windows 版本时使用的构建脚本。  以下是可能导致开发者或高级用户接触到这个脚本的场景：

1. **Frida 开发或贡献者:**  Frida 的开发人员或想要为其贡献代码的人员，需要在本地构建 Frida 的安装包进行测试或发布。他们会按照 Frida 项目的构建文档，执行相应的命令，这些命令最终会调用到 `createmsi.py`。

2. **自定义 Frida 构建:**  一些高级用户可能需要修改 Frida 的源代码或打包配置，然后自行构建安装包。他们会克隆 Frida 的代码仓库，并研究构建脚本，`createmsi.py` 就是其中一个重要的脚本。

3. **调试 Frida 安装问题:**  如果用户在使用 Frida 的 Windows 安装包时遇到问题，例如安装失败或安装后无法正常运行，开发者可能会查看这个脚本以了解安装包的生成过程，寻找潜在的错误来源。例如，他们可能会检查 WiX 描述文件是否正确生成，或者依赖项是否被正确包含。

4. **自动化构建流程:**  在 Frida 的持续集成 (CI) 系统中，这个脚本会被自动化地执行，以生成每个版本或提交的 Windows 安装包。如果构建过程出现问题，CI 系统的日志会显示与这个脚本相关的错误信息。

**总结:**

`createmsi.py` 是 Frida 项目中一个关键的构建脚本，负责将 Frida 打包成 Windows 平台上的 MSI 安装包。 虽然其直接作用域是 Windows 打包，但理解其功能有助于理解 Frida 的安装过程、依赖关系以及工具链的组成部分，这对于逆向分析、理解底层操作系统机制以及进行软件开发和调试都是有益的。

### 提示词
```
这是目录为frida/releng/meson/packaging/createmsi.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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