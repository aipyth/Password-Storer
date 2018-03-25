import sys

from ctypes import *
from obj import *

if __name__ == '__main__':
    h = windll.Kernel32.GetStdHandle(c_ulong(0xfffffff5))
    windll.Kernel32.SetConsoleTitleW(c_wchar_p('Password Saver'))
    windll.Kernel32.SetConsoleTextAttribute(h, 11)
    data = Data()
    aliases = Aliases()
    data.write_in()
    aliases.write_in()
    print('  Password Storer [console version]\n')
    windll.Kernel32.SetConsoleTextAttribute(h, 14)
    while True:
        request = input('($): ').split()
        try:
            if request[0].lower() == 'exit':
                data.write_in()
                aliases.write_in()
                sys.exit()
            if request[0].lower() == 'help':
                print('(:) Open any file in directory \'help\'')
                continue
        except IndexError:
            continue

        for command in aliases():
            if request[0] in command:
                eval(command[0].format(address=None, password=None))
                data.write_in()
                aliases.write_in()
