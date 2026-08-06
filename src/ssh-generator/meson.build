# SPDX-License-Identifier: LGPL-2.1-or-later

executable(
        'systemd-ssh-generator',
        'ssh-generator.c',
        'ssh-util.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : systemgeneratordir)

executable(
        'systemd-ssh-issue',
        'ssh-issue.c',
        'ssh-util.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

executable(
        'systemd-ssh-proxy',
        'ssh-proxy.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

custom_target(
        '20-systemd-ssh-proxy.conf',
        input : '20-systemd-ssh-proxy.conf.in',
        output : '20-systemd-ssh-proxy.conf',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : true,
        install_dir : rootlibexecdir / 'ssh_config.d')

meson.add_install_script('sh', '-c',
                          mkdir_p.format(sshconfdir))

meson.add_install_script(meson_make_symlink,
        rootlibexecdir / 'ssh_config.d' / '20-systemd-ssh-proxy.conf',
        sshconfdir / '20-systemd-ssh-proxy.conf')
