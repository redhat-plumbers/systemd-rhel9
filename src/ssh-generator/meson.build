# SPDX-License-Identifier: LGPL-2.1-or-later

executable(
        'systemd-ssh-generator',
        'ssh-generator.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : systemgeneratordir)
