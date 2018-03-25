import math, re, pyperclip, time, random

class Data(object):
    def __init__(self):
        self.EmptyFileFlag = True
        try:
            with open("data.in", 'r') as fl:
                self.eData = fl.read()
                if self.eData != '':
                    self.eData = eval(core.rb_decrypt(self.eData))
                    self.EmptyFileFlag = False
                else:
                    self.eData = []
        except FileNotFoundError:                                               # if the programm is running first time
            with open("data.in", 'w') as fl:
                self.eData = []

    def __call__(self):
        return self.eData

    def __setitem__(self, offset, value):
        self.eData[offset] = value

    def __getitem__(self, offset, *key):
        if key:
            return self.eData[offset][key]
        return self.eData[offset]

    def write_in(self, sequence=None):                                          # writing data into the file
        if sequence == None:
            sequence = self.eData
        with open("data.in", 'w') as fl:
            sequence = core.rb_encrypt(str(sequence))
            return fl.write(sequence)

class Aliases(object):
    def __init__(self):
        try:
            with open("aliases.in", 'r+') as fl:
                self.aliases = fl.read()
                if self.aliases != '':
                    self.aliases = eval(core.rb_decrypt(self.aliases))
                else:
                    self.aliases = [['guide.create', 'create'], ['guide.clear', 'clear'],
                     ['guide.edit', 'edit'], ['guide.get', 'get'],
                     ['guide.info', 'info'], ['guide.history', 'history']]
                    self.write_in()
        except FileNotFoundError:                                               # if the programm is running first time
            with open("aliases.in", 'w') as fl:
                self.aliases = [['guide.create(data, {address}, {password})', 'create'],
                 ['guide.clear(data, {address})', 'clear'], ['guide.edit(data, {address})', 'edit'],
                 ['guide.get(data, {address})', 'get'], ['guide.info(data, {address})', 'info'],
                 ['guide.history(data, {address})', 'history']]
                self.write_in()

    def __call__(self):
        return self.aliases

    def __setitem__(self, offset, value):
        self.aliases[offset] = value

    def __getitem__(self, offset, *key):
        if key:
            return self.aliases[offset][key]
        return self.aliases[offset]

    def write_in(self):                                          # writing data into the file
        sequence = self.aliases
        with open("aliases.in", 'w') as fl:
            sequence = core.rb_encrypt(str(sequence))
            return fl.write(sequence)

class guide:

    def alias(self, ald_com, new_com):
        pass

    def clear(data, address=None):
        eData = data.eData
        if address == None:
            address = input('($) Enter address: ')
            if address == '':
                print('(!) Deletion intercepted')
                return
        if address == 'all':
            for counter in range(len(eData)):
                item = eData[0]
                core.delete(data, 0)
                print('(!) Deleted {}'.format(item['address']))
            return
        try:
            cert_entries, uncert_entries = core.search(data, address)
        except:
            print('(!) Deletion intercepted')
            return

        if core.is_empty(cert_entries) and core.is_empty(uncert_entries):   # if all lists r empty
            print('(!) No matches found')                                   # print that no matches were found
            return

        if len(cert_entries) == 1:
            item = eData[cert_entries[0]]['address']
            core.delete(data, cert_entries[0])
            print("(!) Deleted {}".format(item))
            return

        if len(uncert_entries) == 1:
            item = eData[uncert_entries[0]]['address']
            ans = input('($) Did you mean {}? (y/n):'.format(item))
            if ans[0].lower() == 'y':
                core.delete(data, uncert_entries[0])
                print("(!) Deleted {}".format(item))
                return
            print('(!) Deletion intercepted')
            return

        if len(cert_entries) > 1 or len(uncert_entries) > 1:
            print('(:) Please write more definite request. There are {} overlaps'.format(
            len(cert_entries) + len(uncert_entries)))
            return

    def create(data, address=None, password=None):
        pass_created = False
        if address and password:
            core.create(data, address, password)
            print('(!) Entry {} created'.format(address))
            return

        address = input('($) Address: ')
        if address == '': print('(!) Creation intercepted')
        password = input('($) Password: ')
        if password == '*':
            password = core.get_password()
            pass_created = True
        core.create(data, address, password)
        print('(!) Entry {} created'.format(address))
        if pass_created: guide.copy_pass(data, -1)
        return

    def edit(data, address=None):
        eData = data.eData
        if address == None:
            address = input('($) Enter address: ')
            if address == '':
                print('(!) Editing intercepted')
                return

        cert_entries, uncert_entries = core.search(data, address)

        if core.is_empty(cert_entries) and core.is_empty(uncert_entries):   # if all lists r empty
            print('(!) No matches found')                                   # print that no matches were found
            return

        if len(cert_entries) == 1:
            item = eData[cert_entries[0]]['address']
            password = input('($) Enter new password for {}: '.format(
            item))
            if password == '*': password = core.get_password()
            core.edit(data, cert_entries[0], item, password)
            print("(!) Edited {}".format(item))
            return

        if len(uncert_entries) == 1:
            item = eData[uncert_entries[0]]['address']
            ans = input('($) Did you mean {}? (y/n):'.format(item))
            if ans[0].lower() == 'y':
                password = input('($) Enter new password for {}: '.format(
                item))
                if password == '*': password = core.get_password()
                core.edit(data, uncert_entries[0], item, password)
                print("(!) Edited {}".format(item))
                return
            print('(!) Editing intercepted')
            return

        if len(cert_entries) > 1 or len(uncert_entries) > 1:
            print('(:) Please write more definite request. There are {} overlaps'.format(
            len(cert_entries) + len(uncert_entries)))
            return

    def info(data, address=None):
        eData = data.eData
        if address == None:
            address = input('($) Enter address: ')
            if address == '':
                print('(!) Intercepted')
                return
        if address == 'all':
            adrss = [eData[offset]['address'] for offset, item in enumerate(eData)]
            longest = core.detect_longest(adrss)
            for offset, value in enumerate(eData):
                print('(i) offset: {}; address: {}; password (encrypted): {};\
\n    created: {}; last time edited: {}'.format(offset,
                eData[offset]['address'], eData[offset]['password'],
                eData[offset]['created'], eData[offset]['edited'] ))
            return

        cert_entries, uncert_entries = core.search(data, address)

        adrss = [eData[offset]['address'] for offset in cert_entries]
        longest = core.detect_longest(adrss)
        for count, offset in enumerate(cert_entries):
            print('(i) offset: {}; address: {}; password (encrypted): {};\
\n    created: {}; last time edited: {}'.format(offset,
            eData[offset]['address'], eData[offset]['password'],
            eData[offset]['created'], eData[offset]['edited'] ))

        adrss = [eData[offset]['address'] for offset in uncert_entries]
        longest = core.detect_longest(adrss)
        for count, offset in enumerate(uncert_entries):
            print('(i) offset: {}; address: {}; password (encrypted): {};\
\n    created: {}; last time edited: {}'.format(offset,
            eData[offset]['address'], eData[offset]['password'],
            eData[offset]['created'], eData[offset]['edited'] ))

    def get(data, address=None):
        eData = data.eData
        if address == None:
            address = input('($) Enter address: ')
            if address == '':
                print('(!) Intercepted')
                return
        cert_entries, uncert_entries = core.search(data, address)

        if core.is_empty(cert_entries) and core.is_empty(uncert_entries):       # if all lists r empty
            print('(!) No matches found')                                       # print that no matches were found
            return

        if len(cert_entries) == 1:
            guide.copy_pass(data, cert_entries[0])
            return

        if len(uncert_entries) == 1:
            item = eData[uncert_entries[0]]['address']
            ans = input('($) Did you mean {}? (y/n):'.format(item))
            if ans[0].lower() == 'y':
                guide.copy_pass(data, uncert_entries[0])
                return
            print('(!) Intercepted')
            return

        if len(cert_entries) > 1 or len(uncert_entries) > 1:
            print('(:) Please write more definite request. There are {} overlaps'.format(
            len(cert_entries) + len(uncert_entries)))
            return

    def history(data, address=None):
        eData = data.eData
        if address == None:
            address = input('($) Enter address: ')
            if address == '':
                print('(!) Intercepted')
                return
        if address == 'all':
            adrss = [eData[offset]['address'] for offset, item in enumerate(eData)]
            longest = core.detect_longest(adrss)
            for offset, value in enumerate(eData):
                print('(i) {} : {} | {}'.format(offset,
                core.adding_spaces(eData[offset]['address'], len(longest)),
                core.rb_decrypt(eData[offset]['password'])))
            return

        cert_entries, uncert_entries = core.search(data, address)

        adrss = [eData[offset]['address'] for offset in cert_entries]
        longest = core.detect_longest(adrss)
        for count, offset in enumerate(cert_entries):
            print('(i) {} : {} | {}'.format(offset,
            core.adding_spaces(eData[offset]['address'], len(longest)),
            core.rb_decrypt(eData[offset]['password'])))

        adrss = [eData[offset]['address'] for offset in uncert_entries]
        longest = core.detect_longest(adrss)
        for count, offset in enumerate(uncert_entries):
            print('(i) {} : {} | {}'.format(offset,
            core.adding_spaces(eData[offset]['address'], len(longest)),
            core.rb_decrypt(eData[offset]['password'])))

    def copy_pass(data, offset):
        pyperclip.copy(core.rb_decrypt(data.eData[offset]['password']))
        print('(!) Password from {} has been copied into the clipboard'.format(
        data.eData[offset]['address']))

class core():

    def create(data, address, password):                                        # create object in eData
        curr_time = core.get_time()
        password = core.rb_encrypt(password)
        dict_obj = dict([('address', address), ('password', password),
                         ('created', curr_time), ('edited', 'None')])
        data.eData.append(dict_obj)

    def delete(data, offset):                                                   # delete object in eData
        del data.eData[offset]                                                  # offset - number of object in eData

    def edit(data, offset, address, password):                                  # edit object in eData:
        curr_time = core.get_time()                                            # offset - number of object in eData
        password = core.rb_encrypt(password)
        data.eData[offset]['address'] = address
        data.eData[offset]['password'] = password
        data.eData[offset]['edited'] = curr_time

    def search(data, address):
        uncert_entries = []
        cert_entries = []
        eData = data.eData
        for offset, obj in enumerate(eData):                                    # Searching address
            if address.lower() == obj['address'].lower():
                cert_entries.append(offset)
            elif address.lower() in obj['address'].lower():
                uncert_entries.append(offset)
            elif obj['address'].lower() in address.lower():
                uncert_entries.append(offset)
        return cert_entries, uncert_entries

    def get_password():
        letters = list('ABCDEFGHIKLMNOPQRSTVXYZabcdefghiklmnopqrstvxyz01234567890123456789')
        random.shuffle(letters)
        return ''.join(letters[:8])

    def rb_encrypt(sequence):
        rList = []
        TypeErrorFlag = False
        if type(sequence) != list:                                              # If sequence is an string, so we must
            sequence = list(sequence)                                           # transform it to the list
            TypeErrorFlag = True                                                # Flag that transformation was successful
        for counter, i in enumerate(sequence):                                  # Making list of code elements of chars
            sequence[counter] = ord(i)
        rList = [sequence[-(element + 1)] for element in range(len(sequence))]  # Reversing it
        key = rList[-1]                                                         # Last dword is an key (needed for decryption)
        for counter, i in enumerate(rList):
            rList[counter] = hex(rList[counter] * key)                          # Simple encryption
        for counter, i in enumerate(rList):
            assert len(i) <= 6, "Code of unicode char is too long"              # If some number_of_char * key gives us
                                                                                # a very big number (bigger than 0xFFFF)
                                                                                # we must interrupt the encryption
            rList[counter] = re.sub('0x', '', i)                                # Deleting all 0x
            rList[counter] = core.adding_zeros(rList[counter])                  # and adding zeros if code is like 3a8
                                                                                # would be like 03a8
        if TypeErrorFlag: rList = ''.join(rList)
        return rList

    def rb_decrypt(sequence):
        TypeErrorFlag = False
        if type(sequence) == str:
            tempLst = []
            for i in range(int(len(sequence) / 4)):
                shift = i * 4
                tempLst.append(sequence[shift:shift + 4])
            sequence = tempLst
            TypeErrorFlag = True
        for counter, i in enumerate(sequence):                                  # adding 0x back
            sequence[counter] = core.adding_hex(i)
        key = int(math.sqrt(eval(sequence[-1])))                                # key is at the end of sequence
        for counter, i in enumerate(sequence):                                  # decrypting back
            sequence[counter] = int(eval(i) / key)
        for counter, i in enumerate(sequence):
            sequence[counter] = chr(i)
        rList = [sequence[-(element + 1)] for element in range(len(sequence))]  # reversing the list
        if TypeErrorFlag: rList = ''.join(rList)
        return rList

    def adding_zeros(string, lenth=4):
        if len(string) < lenth:
            string = '0' + string
            if len(string) < lenth: core.adding_zeros(string)
        return string

    def adding_hex(string):
        string = '0x' + string
        return string

    def adding_spaces(string, value):
        if len(string) != value:
            string = string + ' '
            if len(string) != value:
                return core.adding_spaces(string, value)
        return string

    def is_empty(sequence):
        if len(sequence) == 0:
            return True
        return False

    def get_time():
        curr_time = time.localtime()
        month = core.adding_zeros(str(curr_time.tm_mon), 2)
        mday = core.adding_zeros(str(curr_time.tm_mday), 2)
        tm_hour = core.adding_zeros(str(curr_time.tm_hour), 2)
        tm_min = core.adding_zeros(str(curr_time.tm_min), 2)
        tm_sec = core.adding_zeros(str(curr_time.tm_sec), 2)
        curr_time = str(curr_time.tm_year) + '.' + str(month) + \
        '.' + str(mday) + '(' + str(tm_hour) + ':' + \
        str(tm_min) + ':' + str(tm_sec) +')'
        return curr_time

    def detect_longest(sequence):
        try:
            l_counter = sequence[0]
        except IndexError:
            return None
        for i in sequence:
            if len(i) > len(l_counter): l_counter = i
        return l_counter
