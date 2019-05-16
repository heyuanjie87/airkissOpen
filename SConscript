Import('RTT_ROOT')
Import('rtconfig')
from building import *

cwd = GetCurrentDir()
CPPPATH = [cwd]

src = Split('''
        airkiss.c
        ''')

if GetDepend('AIRKISS_OPEN_DEMO_ENABLE'):
    src += ['osdep/rtthread/airkiss_demo.c']

group = DefineGroup('airkissOpen', src, depend = ['PKG_USING_AIRKISS_OPEN'], CPPPATH = CPPPATH)

Return('group')
