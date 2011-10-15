#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Autowaf, useful waf utilities with support for recursive projects
# Copyright 2008-2011 David Robillard
#
# Licensed under the GNU GPL v2 or later, see COPYING file for details.

import os
import subprocess
import sys

from waflib import Configure, Context, Logs, Node, Options, Task, Utils
from waflib.TaskGen import feature, before, after

global g_is_child
g_is_child = False

# Only run autowaf hooks once (even if sub projects call several times)
global g_step
g_step = 0

# Compute dependencies globally
#import preproc
#preproc.go_absolute = True

@feature('c', 'cxx')
@after('apply_incpaths')
def include_config_h(self):
    self.env.append_value('INCPATHS', self.bld.bldnode.abspath())

def set_options(opt):
    "Add standard autowaf options if they havn't been added yet"
    global g_step
    if g_step > 0:
        return

    # Install directory options
    dirs_options = opt.add_option_group('Installation directories', '')

    # Move --prefix and --destdir to directory options group
    for k in ('--prefix', '--destdir'):
        option = opt.parser.get_option(k)
        if option:
            opt.parser.remove_option(k)
            dirs_options.add_option(option)

    # Standard directory options
    dirs_options.add_option('--bindir', type='string',
                            help="Executable programs [Default: PREFIX/bin]")
    dirs_options.add_option('--configdir', type='string',
                            help="Configuration data [Default: PREFIX/etc]")
    dirs_options.add_option('--datadir', type='string',
                            help="Shared data [Default: PREFIX/share]")
    dirs_options.add_option('--includedir', type='string',
                            help="Header files [Default: PREFIX/include]")
    dirs_options.add_option('--libdir', type='string',
                            help="Libraries [Default: PREFIX/lib]")
    dirs_options.add_option('--mandir', type='string',
                            help="Manual pages [Default: DATADIR/man]")
    dirs_options.add_option('--docdir', type='string',
                            help="HTML documentation [Default: DATADIR/doc]")

    # Build options
    opt.add_option('--debug', action='store_true', default=False, dest='debug',
                   help="Build debuggable binaries [Default: False]")
    opt.add_option('--grind', action='store_true', default=False, dest='grind',
                   help="Run tests in valgrind [Default: False]")
    opt.add_option('--strict', action='store_true', default=False, dest='strict',
                   help="Use strict compiler flags and show all warnings [Default: False]")
    opt.add_option('--docs', action='store_true', default=False, dest='docs',
                   help="Build documentation - requires doxygen [Default: False]")

    # LV2 options
    opt.add_option('--lv2-user', action='store_true', default=False, dest='lv2_user',
                   help="Install LV2 bundles to user-local location [Default: False]")
    if sys.platform == "darwin":
        opt.add_option('--lv2dir', type='string',
                       help="LV2 bundles [Default: /Library/Audio/Plug-Ins/LV2]")
    elif sys.platform == "win32":
        opt.add_option('--lv2dir', type='string',
                       help="LV2 bundles [Default: C:\Program Files\LV2]")
    else:
        opt.add_option('--lv2dir', type='string',
                       help="LV2 bundles [Default: LIBDIR/lv2]")
    g_step = 1

def check_header(conf, lang, name, define='', mandatory=True):
    "Check for a header"
    includes = '' # search default system include paths
    if sys.platform == "darwin":
        includes = '/opt/local/include'

    if lang == 'c':
        check_func = conf.check_cc
    elif lang == 'cxx':
        check_func = conf.check_cxx
    else:
        Logs.error("Unknown header language `%s'" % lang)
        return

    if define != '':
        check_func(header_name=name, includes=includes,
                   define_name=define, mandatory=mandatory)
    else:
        check_func(header_name=name, includes=includes, mandatory=mandatory)

def nameify(name):
    return name.replace('/', '_').replace('++', 'PP').replace('-', '_').replace('.', '_')

def define(conf, var_name, value):
    conf.define(var_name, value)
    conf.env[var_name] = value

def check_pkg(conf, name, **args):
    "Check for a package iff it hasn't been checked for yet"
    var_name = 'CHECKED_' + nameify(args['uselib_store'])
    check = not var_name in conf.env
    conf.env[var_name] = True
    if not check and 'atleast_version' in args:
        # Re-check if version is newer than previous check
        checked_version = conf.env['VERSION_' + name]
        if checked_version and checked_version < args['atleast_version']:
            check = True;
    if check:
        conf.check_cfg(package=name, args="--cflags --libs", **args)
        if 'atleast_version' in args:
            conf.env['VERSION_' + name] = args['atleast_version']

def normpath(path):
    if sys.platform == 'win32':
        return os.path.normpath(path).replace('\\', '\\\\')
    else:
        return os.path.normpath(path)

def configure(conf):
    global g_step
    if g_step > 1:
        return
    def append_cxx_flags(vals):
        conf.env.append_value('CFLAGS', vals.split())
        conf.env.append_value('CXXFLAGS', vals.split())
    print('')
    display_header('Global Configuration')

    if Options.options.docs:
        conf.load('doxygen')

    conf.env['DOCS'] = Options.options.docs
    conf.env['DEBUG'] = Options.options.debug
    conf.env['STRICT'] = Options.options.strict
    conf.env['PREFIX'] = os.path.normpath(os.path.abspath(os.path.expanduser(conf.env['PREFIX'])))

    if sys.platform == 'win32':
        conf.env['PREFIX'] = conf.env['PREFIX'].replace('\\', '\\\\')

    def config_dir(var, opt, default):
        if opt:
            conf.env[var] = normpath(opt)
        else:
            conf.env[var] = normpath(default)

    opts   = Options.options
    prefix = conf.env['PREFIX']

    config_dir('BINDIR',     opts.bindir,     os.path.join(prefix, 'bin'))
    config_dir('SYSCONFDIR', opts.configdir,  os.path.join(prefix, 'etc'))
    config_dir('DATADIR',    opts.datadir,    os.path.join(prefix, 'share'))
    config_dir('INCLUDEDIR', opts.includedir, os.path.join(prefix, 'include'))
    config_dir('LIBDIR',     opts.libdir,     os.path.join(prefix, 'lib'))
    config_dir('MANDIR',     opts.mandir,     os.path.join(conf.env['DATADIR'], 'man'))
    config_dir('DOCDIR',     opts.docdir,     os.path.join(conf.env['DATADIR'], 'doc'))

    if Options.options.lv2dir:
        conf.env['LV2DIR'] = Options.options.lv2dir
    else:
        if Options.options.lv2_user:
            if sys.platform == "darwin":
                conf.env['LV2DIR'] = os.path.join(os.getenv('HOME'), 'Library/Audio/Plug-Ins/LV2')
            elif sys.platform == "win32":
                conf.env['LV2DIR'] = os.path.join(os.getenv('APPDATA'), 'LV2')
            else:
                conf.env['LV2DIR'] = os.path.join(os.getenv('HOME'), '.lv2')
        else:
            if sys.platform == "darwin":
                conf.env['LV2DIR'] = '/Library/Audio/Plug-Ins/LV2'
            elif sys.platform == "win32":
                conf.env['LV2DIR'] = os.path.join(os.getenv('PROGRAMFILES'), 'LV2')
            else:
                conf.env['LV2DIR'] = os.path.join(conf.env['LIBDIR'], 'lv2')

    if Options.options.docs:
        doxygen = conf.find_program('doxygen')
        if not doxygen:
            conf.fatal("Doxygen is required to build with --docs")

        dot = conf.find_program('dot')
        if not dot:
            conf.fatal("Graphviz (dot) is required to build with --docs")

    if Options.options.debug:
        conf.env['CFLAGS'] = [ '-O0', '-g' ]
        conf.env['CXXFLAGS'] = [ '-O0',  '-g' ]
    else:
        append_cxx_flags('-DNDEBUG')

    if Options.options.strict:
        conf.env.append_value('CFLAGS', [ '-std=c99', '-pedantic' ])
        conf.env.append_value('CXXFLAGS', [ '-ansi', '-Woverloaded-virtual', '-Wnon-virtual-dtor'])
        append_cxx_flags('-Wall -Wextra -Wno-unused-parameter')

    append_cxx_flags('-fshow-column')

    conf.env.prepend_value('CFLAGS', '-I' + os.path.abspath('.'))
    conf.env.prepend_value('CXXFLAGS', '-I' + os.path.abspath('.'))

    display_msg(conf, "Install prefix", conf.env['PREFIX'])
    display_msg(conf, "Debuggable build", str(conf.env['DEBUG']))
    display_msg(conf, "Strict compiler flags", str(conf.env['STRICT']))
    display_msg(conf, "Build documentation", str(conf.env['DOCS']))
    print('')

    g_step = 2

def set_local_lib(conf, name, has_objects):
    var_name = 'HAVE_' + nameify(name.upper())
    define(conf, var_name, 1)
    if has_objects:
        if type(conf.env['AUTOWAF_LOCAL_LIBS']) != dict:
            conf.env['AUTOWAF_LOCAL_LIBS'] = {}
        conf.env['AUTOWAF_LOCAL_LIBS'][name.lower()] = True
    else:
        if type(conf.env['AUTOWAF_LOCAL_HEADERS']) != dict:
            conf.env['AUTOWAF_LOCAL_HEADERS'] = {}
        conf.env['AUTOWAF_LOCAL_HEADERS'][name.lower()] = True

def append_property(obj, key, val):
    if hasattr(obj, key):
        setattr(obj, key, getattr(obj, key) + val)
    else:
        setattr(obj, key, val)

def use_lib(bld, obj, libs):
    abssrcdir = os.path.abspath('.')
    libs_list = libs.split()
    for l in libs_list:
        in_headers = l.lower() in bld.env['AUTOWAF_LOCAL_HEADERS']
        in_libs    = l.lower() in bld.env['AUTOWAF_LOCAL_LIBS']
        if in_libs:
            append_property(obj, 'use', ' lib%s ' % l.lower())
            append_property(obj, 'framework', bld.env['FRAMEWORK_' + l])
        if in_headers or in_libs:
            inc_flag = '-iquote ' + os.path.join(abssrcdir, l.lower())
            for f in ['CFLAGS', 'CXXFLAGS']:
                if not inc_flag in bld.env[f]:
                    bld.env.prepend_value(f, inc_flag)
        else:
            append_property(obj, 'uselib', ' ' + l)

def display_header(title):
    Logs.pprint('BOLD', title)

def display_msg(conf, msg, status = None, color = None):
    color = 'CYAN'
    if type(status) == bool and status or status == "True":
        color = 'GREEN'
    elif type(status) == bool and not status or status == "False":
        color = 'YELLOW'
    Logs.pprint('BOLD', " *", sep='')
    Logs.pprint('NORMAL', "%s" % msg.ljust(conf.line_just - 3), sep='')
    Logs.pprint('BOLD', ":", sep='')
    Logs.pprint(color, status)

def link_flags(env, lib):
    return ' '.join(map(lambda x: env['LIB_ST'] % x, env['LIB_' + lib]))

def compile_flags(env, lib):
    return ' '.join(map(lambda x: env['CPPPATH_ST'] % x, env['INCLUDES_' + lib]))

def set_recursive():
    global g_is_child
    g_is_child = True

def is_child():
    global g_is_child
    return g_is_child

# Pkg-config file
def build_pc(bld, name, version, version_suffix, libs, subst_dict={}):
    '''Build a pkg-config file for a library.
    name           -- uppercase variable name     (e.g. 'SOMENAME')
    version        -- version string              (e.g. '1.2.3')
    version_suffix -- name version suffix         (e.g. '2')
    libs           -- string/list of dependencies (e.g. 'LIBFOO GLIB')
    '''
    pkg_prefix       = bld.env['PREFIX']
    if pkg_prefix[-1] == '/':
        pkg_prefix = pkg_prefix[:-1]

    target = name.lower()
    if version_suffix != '':
        target += '-' + version_suffix
    target += '.pc'

    libdir = bld.env['LIBDIR']
    if libdir.startswith(pkg_prefix):
        libdir = libdir.replace(pkg_prefix, '${exec_prefix}')

    includedir = bld.env['INCLUDEDIR']
    if includedir.startswith(pkg_prefix):
        includedir = includedir.replace(pkg_prefix, '${prefix}')

    obj = bld(features     = 'subst',
              source       = '%s.pc.in' % name.lower(),
              target       = target,
              install_path = os.path.join(bld.env['LIBDIR'], 'pkgconfig'),
              exec_prefix  = '${prefix}',
              PREFIX       = pkg_prefix,
              EXEC_PREFIX  = '${prefix}',
              LIBDIR       = libdir,
              INCLUDEDIR   = includedir)

    if type(libs) != list:
        libs = libs.split()

    subst_dict[name + '_VERSION'] = version
    subst_dict[name + '_MAJOR_VERSION'] = version[0:version.find('.')]
    for i in libs:
        subst_dict[i + '_LIBS']   = link_flags(bld.env, i)
        lib_cflags = compile_flags(bld.env, i)
        if lib_cflags == '':
            lib_cflags = ' '
        subst_dict[i + '_CFLAGS'] = lib_cflags

    obj.__dict__.update(subst_dict)

# Doxygen API documentation
def build_dox(bld, name, version, srcdir, blddir):
    if not bld.env['DOCS']:
        return

    if is_child():
        src_dir = os.path.join(srcdir, name.lower())
        doc_dir = os.path.join(blddir, name.lower(), 'doc')
    else:
        src_dir = srcdir
        doc_dir = os.path.join(blddir, 'doc')

    subst_tg = bld(features     = 'subst',
                   source       = 'doc/reference.doxygen.in',
                   target       = 'doc/reference.doxygen',
                   install_path = '',
                   name         = 'doxyfile')

    subst_dict = {
        name + '_VERSION' : version,
        name + '_SRCDIR'  : os.path.abspath(src_dir),
        name + '_DOC_DIR' : os.path.abspath(doc_dir)
        }

    subst_tg.__dict__.update(subst_dict)

    subst_tg.post()

    docs = bld(features = 'doxygen',
               doxyfile = 'doc/reference.doxygen')

    docs.post()

    bld.install_files('${DOCDIR}/%s/html' % name.lower(),
                      bld.path.get_bld().ant_glob('doc/html/*'))
    bld.install_files('${MANDIR}/man1',
                      bld.path.get_bld().ant_glob('doc/man/man1/*'))
    bld.install_files('${MANDIR}/man3',
                      bld.path.get_bld().ant_glob('doc/man/man3/*'))

# Version code file generation
def build_version_files(header_path, source_path, domain, major, minor, micro):
    header_path = os.path.abspath(header_path)
    source_path = os.path.abspath(source_path)
    text  = "int " + domain + "_major_version = " + str(major) + ";\n"
    text += "int " + domain + "_minor_version = " + str(minor) + ";\n"
    text += "int " + domain + "_micro_version = " + str(micro) + ";\n"
    try:
        o = open(source_path, 'w')
        o.write(text)
        o.close()
    except IOError:
        Logs.error('Failed to open %s for writing\n' % source_path)
        sys.exit(-1)

    text  = "#ifndef __" + domain + "_version_h__\n"
    text += "#define __" + domain + "_version_h__\n"
    text += "extern const char* " + domain + "_revision;\n"
    text += "extern int " + domain + "_major_version;\n"
    text += "extern int " + domain + "_minor_version;\n"
    text += "extern int " + domain + "_micro_version;\n"
    text += "#endif /* __" + domain + "_version_h__ */\n"
    try:
        o = open(header_path, 'w')
        o.write(text)
        o.close()
    except IOError:
        Logs.warn('Failed to open %s for writing\n' % header_path)
        sys.exit(-1)

    return None

def cd_to_build_dir(ctx, appname):
    orig_dir  = os.path.abspath(os.curdir)
    top_level = (len(ctx.stack_path) > 1)
    if top_level:
        os.chdir('./build/' + appname)
    else:
        os.chdir('./build')
    Logs.pprint('GREEN', "Waf: Entering directory `%s'" % os.path.abspath(os.getcwd()))

def cd_to_orig_dir(ctx, child):
    if child:
        os.chdir('../..')
    else:
        os.chdir('..')

def pre_test(ctx, appname, dirs=['./src']):
    diropts  = ''
    for i in dirs:
        diropts += ' -d ' + i
    cd_to_build_dir(ctx, appname)
    clear_log = open('lcov-clear.log', 'w')
    try:
        # Clear coverage data
        subprocess.call(('lcov %s -z' % diropts).split(),
                        stdout=clear_log, stderr=clear_log)
    except:
        Logs.warn('Failed to run lcov, no coverage report will be generated')
    finally:
        clear_log.close()

def post_test(ctx, appname, dirs=['./src']):
    diropts  = ''
    for i in dirs:
        diropts += ' -d ' + i
    coverage_log           = open('lcov-coverage.log', 'w')
    coverage_lcov          = open('coverage.lcov', 'w')
    coverage_stripped_lcov = open('coverage-stripped.lcov', 'w')
    try:
        base = '.'
        if g_is_child:
            base = '..'
        # Generate coverage data
        subprocess.call(('lcov -c %s -b %s' % (diropts, base)).split(),
                        stdout=coverage_lcov, stderr=coverage_log)

        # Strip unwanted stuff
        subprocess.call('lcov --remove coverage.lcov *boost* c++*'.split(),
                        stdout=coverage_stripped_lcov, stderr=coverage_log)

        # Generate HTML coverage output
        if not os.path.isdir('./coverage'):
            os.makedirs('./coverage')
        subprocess.call('genhtml -o coverage coverage-stripped.lcov'.split(),
                        stdout=coverage_log, stderr=coverage_log)

    except:
        Logs.warn('Failed to run lcov, no coverage report will be generated')
    finally:
        coverage_stripped_lcov.close()
        coverage_lcov.close()
        coverage_log.close()

        print('')
        Logs.pprint('GREEN', "Waf: Leaving directory `%s'" % os.path.abspath(os.getcwd()))
        top_level = (len(ctx.stack_path) > 1)
        if top_level:
            cd_to_orig_dir(ctx, top_level)

    print('')
    Logs.pprint('BOLD', 'Coverage:', sep='')
    print('<file://%s>\n\n' % os.path.abspath('coverage/index.html'))

def run_tests(ctx, appname, tests, desired_status=0, dirs=['./src'], name='*'):
    failures = 0
    diropts  = ''
    for i in dirs:
        diropts += ' -d ' + i

    # Run all tests
    for i in tests:
        s = i
        if type(i) == type([]):
            s = ' '.join(i)
        print('')
        Logs.pprint('BOLD', '** Test', sep='')
        Logs.pprint('NORMAL', '%s' % s)
        cmd = i
        if Options.options.grind:
            cmd = 'valgrind ' + i
        if subprocess.call(cmd, shell=True) == desired_status:
            Logs.pprint('GREEN', '** Pass')
        else:
            failures += 1
            Logs.pprint('RED', '** FAIL')

    print('')
    if failures == 0:
        Logs.pprint('GREEN', '** Pass: All %s.%s tests passed' % (appname, name))
    else:
        Logs.pprint('RED', '** FAIL: %d %s.%s tests failed' % (failures, appname, name))

def run_ldconfig(ctx):
    if ctx.cmd == 'install':
        print('Running /sbin/ldconfig')
        try:
            os.popen("/sbin/ldconfig")
        except:
            Logs.error('Error running ldconfig, libraries may not be linkable')
