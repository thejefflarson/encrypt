#!/usr/bin/env python


def options(opt):
    opt.load('compiler_c')

def configure(conf):
    conf.load('compiler_c')
    conf.env.append_unique('CFLAGS', ['-std=c99', '-Wall', '-g'])
    conf.env.append_value('INCLUDES', ['include'])


def build(bld):
    bld.program(
        features='c',
        source=bld.path.ant_glob(['src/*.c', 'test/test_encrypt.c']),
        includes=['src'],
        target='test_encrypt',
        install_path=None
    )