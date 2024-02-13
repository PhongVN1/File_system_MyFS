import AES
import os
from datetime import datetime

## phần cấu trúc  
class Header:
    def __init__(self):
        self.Signature = b'.HPQ'        #0  - 4  bytes
        self.SizeOfVolume = b''         #4  - 4  bytes
        self.PassWord = b''             #10 - 32 bytes
class Entry:
    def __init__(self):                 
        self.Name = b''                 #0  - 32 bytes
        self.Extended = b''             #20 - 5  bytes
        self.DateCreate = b''           #25 - 2  bytes
        self.LocationOfData = b''       #27 - 4  bytes
        self.Size=b''                   #2B - 4  bytes
        self.State = b''                #2F - 1  bytes
        self.PassWord = b''             #30 - 32 bytes
class Data:
    def __init__(self):
        self.Data = b''                 #0   - 508 bytes
        self.NextData = b''             #1FC - 4   bytes
## xử lý ngày
def convert_byte_to_date(byte_string):
    combined_value = byte_string[0] + (byte_string[1] << 8)  # Kết hợp 2 byte lại thành một số nguyên
    day = combined_value & 0b00011111  # 5 bits lưu ngày
    month = (combined_value >> 5) & 0b00001111  # 4 bits lưu tháng
    year = (combined_value >> 9) + 1980  # 7 bits lưu năm + 1980

    return f"{day}/{month}/{year}"
def convert_date_to_byte(date_string):
    date_object = datetime.strptime(date_string, "%d-%m-%Y")
    day = date_object.day
    month = date_object.month
    year = date_object.year - 1980
    combined_value = (year << 9) | (month << 5) | day
    byte_representation = combined_value.to_bytes(2, byteorder='little')
    return byte_representation
##
## Đọc viết 512 bytes
def read512(path,sector):
    with open(path + "/.HPQ", "rb+") as file:
        file.seek(512*sector)
        return file.read(512)
def write512(path,data,sector):
    with open(path + "/.HPQ", "rb+") as file:
        file.seek(512*sector)
        if len(data) == 512:
            # Ghi chuỗi byte vào file nếu kích thước đúng
            file.write(data)
    file.close()
            # print("Đã ghi 512 byte vào file.")
        # else:
        #     print("Không ghi dữ liệu do kích thước không đúng.")
##
## tìm sector, entry trống   
def is_all_zeros(byte_string):
    return all(byte == 0 for byte in byte_string)
def findEmptySector(path, sector = 1):#Trả về vị trí trên sector trống 
    while True:
        data=read512(path,sector)
        if not data:
            print("End of Volume!")
            return 0
        if(is_all_zeros(data)):
            return sector
        sector = sector + 1
def findEmtryEntry(path,sector): #Trả về vị trí entry trống và sector thứ i 
    entry_size = 80
    while True:
        data=read512(path,sector)
        for i in range(6):
            start = i * entry_size
            end = start + entry_size
            entry = data[start:end]
            if is_all_zeros(entry):
                return start,sector
        if is_all_zeros(data[-4:]):
            sector = findEmptySector(path)
        sector = int.from_bytes(data[-4:], byteorder='big')
##
##Tạo 1 volume ".HPQ"
def padding(string_to_insert,num):
    if len(string_to_insert) >= num:
        return string_to_insert[:num]  # Trả về chuỗi chỉ chứa num ký tự đầu tiên nếu chuỗi đã đủ num ký tự hoặc hơn

    remaining_chars = num - len(string_to_insert)  # Số ký tự cần chèn
    additional_chars = b'\0' * remaining_chars  # Ký tự để chèn vào chuỗi

    return string_to_insert + additional_chars 
def chooseSizeOfVolume():
    sizes = {
    1: 512*400,       # 20480000 bytes ~ 19 mb 40000
    2: 512*800,       # 40960000 bytes ~ 39 mb 80000
    3: 512*1000       # 51200000 bytes ~ 48 mb 100000
    }   
    while True:
        choice = int(input("Chọn dung lượng lưu trữ (1: 512MB, 2: 1GB, 3: 2GB): "))
        if choice in sizes:
            return sizes[choice]
        else:
            print("Vui lòng chỉ chọn từ 1 đến 3. Thử lại.")

def createVolume(path):
    header = Header()
    header.SizeOfVolume = chooseSizeOfVolume().to_bytes(4, byteorder='big')
    option = input("1: Đặt mật khẩu\n2: bỏ qua\n")
    if option == '1':
        temp, header.PassWord = createNewPass()
        print("Tạo mật khẩu thành công")
    else:
        print("Không có mật khẩu")
    dataBlock = padding(padding(header.Signature + header.SizeOfVolume, 16) + header.PassWord,512)
    
    if os.path.exists(path +"/.HPQ"):
        print("Đã tồn tại. Vui lòng chọn đường dẫn khác.")
    else:
        with open(path + "/.HPQ", "wb") as file:
            file.seek(int.from_bytes(header.SizeOfVolume, byteorder='big') - 1)
            file.write(b'\0')
            file.close()
    write512(path,dataBlock,0)
    return header
## đã xong phần tạo volume 
##Mở đọc volume
def readVolume(path):
    data = read512(path, 0)
    header = Header()
    if header.Signature == data[:4]:
        print("Volume hợp lệ")
    else:
        print("Không phải định dạng .HPQ, không đọc được!!!")
        return 1
    header.SizeOfVolume = data[4:8]
    header.PassWord = data[16:48]
    if (is_all_zeros(header.PassWord)):
        return header
    else:
        while(True):
            Pass=input("Nhập mật khẩu để truy cập Volume: ")
            if(AES.sha256_hash_string(Pass) != header.PassWord):
                print("Sai mật khẩu!")
                return 0
            else:
                return header
def encVolume(path, header):
    for i in range(1, int.from_bytes(header.SizeOfVolume, byteorder='big') // 512):
        data = read512(path, i)
        write512(path,AES.dec(padding(header.PassWord, 32),data),i)
def decVolume(path, header):
    for i in range(1, int.from_bytes(header.SizeOfVolume, byteorder='big') // 512):
        data = read512(path, i)
        write512(path,AES.enc(padding(header.PassWord, 32),data),i)
def changeOrDeleteVolumePassword(path, header):
    option = input("1: Thay đổi mật khẩu\n2: Xóa mật khẩu\nNhập lựa chọn của bạn: ")
    
    if option == '1':
        new_password, new_hash = createNewPass()
        if new_password == 0 or new_hash == 0:
            return  # User chose to exit
        
        while True:
            current_password = input("Nhập mật khẩu hiện tại của Volume: ")
            if AES.sha256_hash_string(current_password) != header.PassWord:
                print("Sai mật khẩu!")
            else:
                header.PassWord = new_hash
                encVolume(path, header)
                print("Đã thay đổi mật khẩu của Volume.")
                return
    elif option == '2':
        while True:
            current_password = input("Nhập mật khẩu hiện tại của Volume: ")
            if AES.sha256_hash_string(current_password) != header.PassWord:
                print("Sai mật khẩu!")
            else:
                header.PassWord = b'\x00' * 32
                encVolume(path, header)
                print("Đã xóa mật khẩu của Volume.")
                return
    else:
        print("Lựa chọn không hợp lệ.")


## Đóng mở Entry với passkey !! folder thì không có PassWord

##
## Viết entry
def createEntryBlock(Entry):
    return padding(bytes(Entry.Name),32) + padding(bytes(Entry.Extended),5) + padding(bytes(Entry.DateCreate),2) + padding(bytes(Entry.LocationOfData),4)+ padding(bytes(Entry.Size),4) + padding(bytes(Entry.State),1) +padding(bytes(Entry.PassWord),32)
def replace_bytes(entry_table, entry_block, start_index):
    if start_index + len(entry_block) <= len(entry_table):
        entry_table_after = entry_table[:start_index] + entry_block + entry_table[start_index + len(entry_block):]
        return entry_table_after
    else:
        print("Lỗi! ")
        return 0    
def writeEntry(Entry,path,sector):##Tìm entry trống và sector chứa entry đó
    empty_entry_pos,sector_pos = findEmtryEntry(path,sector)
    entry_table = read512(path,sector_pos)
    entry_block = createEntryBlock(Entry)
    new_entry_table = replace_bytes(entry_table,entry_block,empty_entry_pos)
    write512(path,new_entry_table,sector_pos)# vẫn chưa có vị trí data tiếp theo
    if is_all_zeros(Entry.Size):
        return 0
    else:
        sector = findEmptySector(path, sector)
        p,s=findPosByName(path, Entry.Name.decode('utf-8'))
        final_data_block = replace_bytes(new_entry_table,sector.to_bytes(4, byteorder='big'),39+p)
        write512(path,final_data_block,sector_pos)
        return sector
##
## Viết data
def createNewPass():
    while True:
        newPass = input("Nhập password mới phải nhỏ hơn 16 kí tự(Enter bỏ qua): ")
        if len(newPass) < 16:
            return newPass,AES.sha256_hash_string(newPass)  
        if len(newPass) == 0:
            return 0,0
def changePass(HashPass):
    while True:
        Password = input("Nhập password mới phải nhỏ hơn 16 kí tự(Enter để thoát): ")
        if len(newPass) == 0:
            return 0
        if(AES.sha256_hash_string(Password) == HashPass)and len(Password) < 16:
            newPass = input("Nhập mật khẩu mới: ")
            return AES.sha256_hash_string(newPass)
        else:
            print("Nhập sai mật khẩu")
def encData(path,sector,passKey):
    while True:
        data = read512(path,sector)
        next_sector = data[-4:]
        write512(path,AES.enc(padding(passKey.encode('utf-8'), 32),data),sector)
        sector = int.from_bytes(next_sector, byteorder='big')
        if is_all_zeros(next_sector):
            break
def decData(path,sector,passKey):
    while True:
        data = read512(path,sector)
        next_sector = data[-4:]
        write512(path,AES.dec(padding(passKey.encode('utf-8'), 32),data),sector)
        data = read512(path,sector)
        next_sector = data[-4:]
        sector = int.from_bytes(next_sector, byteorder='big')
        if is_all_zeros(next_sector):
            break
def secure(path, name):
    pos, sector = findPosByName(path, name)
    with open(path + "/.HPQ", "rb+") as file:
        file.seek(512 * sector + pos + 48)
        passWord = file.read(32)

    if is_all_zeros(passWord):
        with open(path + "/.HPQ", "rb+") as file:
            file.seek(512 * sector + pos + 48)
            passKey, passHash = createNewPass()
            file.write(passHash)
            if passKey != 0:  # When setting a new password, encrypt the data
                file.seek(512 * sector + pos + 39)
                data_sector = file.read(4)
                encData(path, int.from_bytes(data_sector, byteorder='big'), passKey)
                return 0
    else:
        print("1: Đổi mật khẩu")
        print("2: Xóa mật khẩu")
        print("3: Thoát")
        choice = input("Nhập lựa chọn: ")
        
        if choice == "3":
            return 0
        
        while True:
            input_password = input("Nhập password phải nhỏ hơn 16 kí tự(Enter để thoát): ")
            if len(input_password) == 0:
                return 0
            if(AES.sha256_hash_string(input_password) == passWord) and len(input_password) < 16:
                if choice == "1":
                    newPass = input("Nhập mật khẩu mới: ")
                break
            else:
                print("Nhập sai mật khẩu")

        if choice == "1":  # Changing password: decrypt data -> encrypt data with new pass
            with open(path + "/.HPQ", "rb+") as file:
                file.seek(512 * sector + pos + 48)
                file.write(AES.sha256_hash_string(newPass))
                if newPass != 0:
                    file.seek(512 * sector + pos + 39)
                    data_sector = file.read(4)
                    decData(path, int.from_bytes(data_sector, byteorder='big'), input_password)  # Decrypt with old pass
                    encData(path, int.from_bytes(data_sector, byteorder='big'), newPass)  # Encrypt with new pass
                    return 0
        elif choice == "2":  # Deleting password: decrypt data
            with open(path + "/.HPQ", "rb+") as file:
                file.seek(512 * sector + pos + 48)
                file.write(b'\x00' * 32)  # Clear password
                file.seek(512 * sector + pos + 39)
                data_sector = file.read(4)
                decData(path, int.from_bytes(data_sector, byteorder='big'), input_password)  # Decrypt data
                return 0
        else:
            return 0
def secureFileByName(path):
    os.system('cls')
    name = input("Nhập tên file / folder cần đổi mật khẩu:")
    secure(path,name)
def splitDataIntoBlocks(data):
    blockList = []
    while data:
        chunk, data = data[:508], data[508:]
        chunk = chunk.ljust(508, b'\0')  # Bổ sung null byte nếu cần
        blockList.append(chunk)
    return blockList
def writeData(data,path,sector):# sector đầu chứa data  
    blockList = splitDataIntoBlocks(data)
    for i in range (len(blockList)):
        block = blockList[i] + b'\0'*4
        write512(path,block,sector)
        if i != (len(blockList)-1):
            new_sector = findEmptySector(path, sector)
            final_data_block = replace_bytes(block,new_sector.to_bytes(4, byteorder='big'),508)
            write512(path,final_data_block,sector)
            sector = new_sector
def readData(path, start_sector):
    data = b""
    while True:
        block = read512(path, start_sector)
        data += block[:508]  # Read the first 508 bytes as data

        next_sector_bytes = block[508:512]  # The last 4 bytes indicate the next sector
        next_sector = int.from_bytes(next_sector_bytes, byteorder='big')

        if next_sector != 0:
            start_sector = next_sector  # Move to the next sector
        else:
            break  # End of data, break the loop
    
    return data.rstrip(b'\0')  # Remove any trailing null byte
def readEntriesInFolder(path, sector):
    # Assuming the folder entries are stored in the volume in a specific way
    # Read entries for a given sector (representing a folder) and return a list of entries
    entries = []
    with open(path, "rb") as file:
        file.seek(512 * sector)  # Assuming each entry is 512 bytes and starts at a specific sector
        while True:
            data = file.read(512)  # Read 512 bytes (size of an entry)
            if len(data) < 512:  # End of file or folder entries
                break
            entry = Entry()  # Assuming there's an Entry class
            entry.Name = data[:32]
            entry.Extended = data[32:37]
            entry.DateCreate = data[37:39]
            entry.LocationOfData = data[39:43]
            entry.Size = data[43:47]
            entry.State = data[47:48]
            entry.PassWord = data[48:]
            entries.append(entry)
    return entries
def findPosByName(path, name):
    sector = 1
    byte_name = name.encode('utf-8')
    byte_name = padding(byte_name,32)
    while True:
        data=read512(path,sector)
        if not data:
            #print("End of Volume!")
            return 0,0
        pos = data.find(byte_name)
        if(pos != -1):
            return pos, sector
        sector = sector + 1
##
## Đọc Entry
def readOneEntry(path,sector,pos): #read 80byte
    entry = Entry()
    data = read512(path,sector)
    
    entryBlock = data[pos: pos + 80]
    
    entry.Name = entryBlock[:32].replace(b'\x00', b'')
    entry.Extended = entryBlock[32:36].replace(b'\x00', b'')
    entry.DateCreate = entryBlock[37:39]
    entry.LocationOfData = entryBlock[39:43].replace(b'\x00', b'')
    entry.Size = entryBlock[43:47].replace(b'\x00', b'')
    entry.State = entryBlock[47:48].replace(b'\x00', b'')
    entry.PassWord = entryBlock[48:]
    return entry
def readAllEntries(path):
    sector = 0  # Starting sector
    entries = []

    while True:
        data = read512(path, sector)
        pos = 0

        while pos < len(data):
            entry = Entry()
            entryBlock = data[pos: pos + 80]
            
            # Populating Entry attributes
            entry.Name = entryBlock[:32].replace(b'\x00', b'')
            entry.Extended = entryBlock[32:37].replace(b'\x00', b'')
            entry.DateCreate = entryBlock[37:39]
            entry.LocationOfData = entryBlock[39:43].replace(b'\x00', b'')
            entry.Size = entryBlock[43:47].replace(b'\x00', b'')
            entry.State = entryBlock[47:48].replace(b'\x00', b'')
            entry.PassWord = entryBlock[48:]
            
            entries.append(entry)
            pos += 80
        
        sector += 1  # Move to the next sector
        
        # Assuming the end condition, you might have a specific criteria to stop the loop
        if not data:
            break

    return entries
# Printing the list of files and folders
def printEntries(entries):
    for i, entry in enumerate(entries, start=1):
        try:
            name = entry.Name.decode('utf-8')
        except UnicodeDecodeError:
            name = entry.Name.decode('utf-8', errors='replace')  # Replace invalid characters

        entry_type = "Folder" if entry.State == b'\x01' else "File" if entry.State == b'\x02' else "Backup" if entry.State == b'\x02' else "Deleted"
        if (entry_type == "File" or entry_type == "Folder"):
            print(f"Name: {name}, Type: {entry_type}")
        
def printDirectoryTree(entries, parent='', depth=0):
    for entry in entries:
        entry_type = "Folder" if entry.State == b'\x01' else "File"
        indent = '  ' * depth

        if parent:
            print(f"{indent}|- {parent}/{entry.Name.decode()} ({entry_type})")
        else:
            print(f"{indent}|- {entry.Name.decode()} ({entry_type})")

        if entry.State == b'\x01':
            printDirectoryTree(entry.children, entry.Name.decode(), depth + 1)

##
## Copy file to volume 
def copyToVolume(path, header):
    while True:
        os.system('cls')
        print("1: Lưu trong thư mục")
        print("2: Không lưu trong thư mục")
        print("3: Tạo thư mục mới")
        print("0: Thoát chương trình")
        choice = input("Nhập lựa chọn của bạn: ")
        if choice == "0":
            break
        file_path = input("Nhập đường dẫn chứa file(ví dụ E:\\report.pdf): ")
        entry = Entry()
        if os.path.exists(file_path):#lưu 1 entry
            entry.Name = os.path.splitext(os.path.basename(file_path))[0].encode('utf-8')
            entry.Extended = os.path.splitext(file_path)[1].encode('utf-8')
            creation_time = os.path.getctime(file_path)
            created_datetime = datetime.fromtimestamp(creation_time)
            created_date = created_datetime.strftime('%d-%m-%Y')
            entry.DateCreate = convert_date_to_byte(created_date)
            entry.Size = os.path.getsize(file_path).to_bytes(4, byteorder='big')
            entry.State = b'\x02'
            if choice == "1":
                input_name = input("Nhập tên thư mục để lưu: ")
                pos,sector = findPosByName(path, input_name)# tìm entry theo tên
                if sector == 0:
                    print("Folder không tồn tại")
                else:
                    folder_entry = readOneEntry(path,sector,pos)# nếu tìm thấy entry thì đọc entry 
                    if is_all_zeros(folder_entry.LocationOfData):# kiểm tra xem entry đó có data chưa (data của folder là bảng entry)
                        new_sector = findEmptySector(path)# chưa thì tìm sector trống để lưu
                        folder_entry.LocationOfData = new_sector.to_bytes(4, byteorder='big')# lưu địa chỉ sector trống đó vào 4byte quy định
                        with open(path + "/.HPQ", "rb+") as file:
                            file.seek(512 * sector + pos + 39)
                            file.write(folder_entry.LocationOfData)
                        
                        data_pos = writeEntry(entry,path,new_sector)# viết entry của file cần lưu vào trả ra vị trí sector trống để lưu data
                        with open(file_path, "rb+") as file:# viết data vào 
                            data = file.read()
                        if data_pos != 0:
                            writeData(data,path,data_pos)
                            writeBackupData(entry, data, path, header)
                        secure(path, (entry.Name).decode('utf-8'))
                    else:
                        pos = writeEntry(entry,path,int.from_bytes(folder_entry.LocationOfData, byteorder='big'))# entry gốc
                        with open(file_path, "rb+") as file:
                            data = file.read()
                        if pos != 0:
                            writeData(data,path,pos,entry.PassWord)
                            writeBackupData(entry, data, path, header)
            elif choice == "2":
                pos = writeEntry(entry,path,1)# entry gốc
                with open(file_path, "rb+") as file:
                    data = file.read()
                if pos != 0:
                    writeData(data,path,pos)
                    writeBackupData(entry, data, path, header)
                secure(path, (entry.Name).decode('utf-8'))
            elif choice == "3":
                input_name = input("Nhập tên thư mục: ")
                pos,sector = findPosByName(path, input_name)# tìm entry theo tên
                if sector == 0:
                    folder_entry = Entry()
                    folder_entry.Name = input_name.encode('utf-8')
                    writeEntry(folder_entry,path,1)
                    secure(path, (folder_entry.Name).decode('utf-8'))
                else:
                    print("Đã tồn tại")              
        if os.name == 'nt':
            os.system('pause')      
def exportFromVolume(path):
    export_path = input("Nhập đường dẫn xuất (ví dụ: /path/to/export): ")

    while True:
        os.system('cls')
        input_name = input("Nhập tên thư mục/file cần xuất (0 để thoát): ")
        if input_name == "0":
            print("Thoát chương trình.")
            break

        pos, sector = findPosByName(path, input_name)  # Find the entry by name
        if sector == 0:
            print("Thư mục/file không tồn tại.")
        else:
            entry = readOneEntry(path, sector, pos)  # Read the entry
            if entry.State == b'\x01':  # If it's a folder
                folder_entries = readEntriesInFolder(path, int.from_bytes(entry.LocationOfData, byteorder='big'))
                print(f"Exporting folder: {entry.Name.decode()} to {export_path}")
                folder_path = os.path.join(export_path, entry.Name.decode())
                os.makedirs(folder_path, exist_ok=True)
                for folder_entry in folder_entries:
                    if folder_entry.State == b'\x02':  # If it's a file
                        password = input(f"Enter password for {folder_entry.Name.decode() + folder_entry.Extended.decode()}: ")
                        if checkFilePassword(path, folder_entry, password):
                            encrypted_data = readData(path, int.from_bytes(folder_entry.LocationOfData, byteorder='big'))
                            decrypted_data = decData(path, int.from_bytes(folder_entry.LocationOfData, byteorder='big'), password)
                            file_name = folder_entry.Name.decode() + folder_entry.Extended.decode()
                            file_path = os.path.join(folder_path, file_name)
                            with open(file_path, "wb") as file:
                                file.write(decrypted_data)
                                print(f"Exported file: {file_path}")
                        else:
                            print("Incorrect password. File cannot be exported.")
            elif entry.State == b'\x02':  # If it's a file
                password = input(f"Enter password for {entry.Name.decode() + entry.Extended.decode()}: ")
                if checkFilePassword(path, entry, password):
                    decData(path, int.from_bytes(entry.LocationOfData, byteorder='big'), password)
                    data = readData(path, int.from_bytes(entry.LocationOfData, byteorder='big'))
                    encData(path, int.from_bytes(entry.LocationOfData, byteorder='big'), password)
                    file_name = entry.Name.decode() + entry.Extended.decode()
                    file_path = os.path.join(export_path, file_name)
                    with open(file_path, "wb") as file:
                        file.write(data)
                        print(f"Exported file: {file_path}")
                else:
                    print("Incorrect password. File cannot be exported.")
            else:
                print("Unknown entry type.")
        if os.name == 'nt':
            os.system('pause')
def checkFilePassword(path, entry, password):
    passWord = getPasswordFromEntry(path, entry)
    return AES.sha256_hash_string(password) == passWord
def getPasswordFromEntry(path, entry):
    pos, sector = findPosByName(path, (entry.Name).decode('utf-8'))
    with open(path + "/.HPQ", "rb+") as file:
        file.seek(512 * sector + pos + 48)
        passWord = file.read(32)
    return passWord
            
def deleteFileFromVolume(path):
    # Search for the file in the volume
    found = False
    while True:
        os.system('cls')
        input_name = input("Nhập tên thư mục/file cần xuất (0 để thoát): ")
        if input_name == "0":
            print("Thoát chương trình.")
            break

        pos, sector = findPosByName(path, input_name)  # Find the entry by name
        if sector != 0:
            entry = readOneEntry(path, sector, pos)  # Read the entry
            if entry.Name.decode('utf-8') == input_name:
                found = True
                print(f"File '{input_name}' được tìm thấy trong MyFS.")
                password = input("Nhập mật khẩu để xóa file: ")
                if checkFilePassword(path, entry, password):
                    confirm = input("Bạn có chắc chắn muốn xóa? (Y/N): ")
                    if confirm.upper() == "Y":
                        if unrecoverableDeletionOption():
                            # Perform unrecoverable deletion
                            performUnrecoverableDeletion(path, entry)
                            print(f"File '{input_name}' đã bị xóa vĩnh viễn khỏi MyFS.")
                        else:
                            # Perform soft deletion
                            performSoftDeletion(path, entry)
                            print(f"File '{input_name}' đã được đánh dấu xóa khỏi MyFS.")
                else:
                    print("Mật khẩu không chính xác. Không thể xóa file.")
                break
    if not found:
        print(f"File '{input_name}' không tồn tại trong MyFS.")
        
def unrecoverableDeletionOption():
    option = input("Bạn muốn xóa vĩnh viễn? (Y/N): ")
    return option.upper() == "Y"

def performUnrecoverableDeletion(path, entry):
    data_start_sector = int.from_bytes(entry.LocationOfData, byteorder='big')

    # Overwrite the entry data with null bytes
    with open(f"{path}/.HPQ", "rb+") as myfs_file:
        myfs_file.seek(512 * data_start_sector)
        myfs_file.write(b'\x00' * 512)  # Overwrite the entry data with null bytes

    # Wipe the data associated with the file
    wipeDataUsingNextData(path, entry.LocationOfData)
    
    # Optionally, update the entry information to indicate deletion by zeroing out relevant data
    # For example, zero out the address sector to mark the entry as deleted
    pos, sector = findPosByName(path, (entry.Name).decode('utf-8'))
    with open(f"{path}/.HPQ", "rb+") as myfs_file:
        myfs_file.seek(512 * sector + pos)
        myfs_file.write(b'\x00' * 80)  # Zero out the address sector to mark the entry as deleted

def wipeDataUsingNextData(path, start_sector):
    # Traverse through the data blocks using NextData and wipe the associated data
    while start_sector != b'\x00\x00\x00\x00':
        sector = int.from_bytes(start_sector, byteorder='big')
        write512(path, b'\x00' * 512, sector)  # Use write512 to wipe the sector with null bytes

        # Update start_sector to the next data block address
        start_sector = readNextData(path, sector)

def readNextData(path, sector):
    with open(path + "/.HPQ", "rb") as myfs_file:
        myfs_file.seek(sector * 512 + 508)  # Position to read NextData attribute
        next_data = myfs_file.read(4)
    return next_data

def performSoftDeletion(path, entry):
    pos, sector = findPosByName(path, (entry.Name).decode('utf-8'))
    # Optionally, update the entry information to indicate deletion
    with open(f"{path}/.HPQ", "rb+") as myfs_file:
        myfs_file.seek(512 * sector + pos + 47)  # Assuming 39 is the offset for the entry status field
        myfs_file.write(b'\x04')  # Update the status field to indicate soft deletion (or use another flag)

# Backup dữ liệu
def posOfBackup(header): # trả về sector bắt đầu vùng backup
    size = int.from_bytes(header.SizeOfVolume, byteorder='big') // 512
    return int(size - (size * 5 / 100))
def writeBackupData(entry, data, path, header):
    print("Lưu file backup?")
    print("1. Lưu")
    print("Khác. Thoát")
    choice = input("Nhập lựa chọn của bạn: ")
    entry.State = b'\x03'
    if choice == "1":
        backupZone = posOfBackup(header)
        pos = writeEntry(entry, path, backupZone)
        if pos != 0:
            writeData(data,path,pos)
    else:
        return
# state \x01 folder | \x02 file | \x03 backup | \x04 delete