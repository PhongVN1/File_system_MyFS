import HPQ
import os

def submenu(path, header):
    while True:
        os.system('cls')
        print(f"_____________ {path}/.HPQ VOLUME _______________")
        print("1. Đổi password volume .HPQ")
        print("2. Liệt kê danh sách file / folder")
        print("3. Đổi password file / folder")
        print("4. Import file")
        print("5. Export file")
        print("6. Xoá file")
        print("0. Quay lại")
        choice = input("Nhập lựa chọn của bạn: ")
        if choice == "1":
            HPQ.changeOrDeleteVolumePassword(path, header)

        elif choice == "2":
            entries = HPQ.readAllEntries(path)
            HPQ.printEntries(entries)
            os.system('pause')
            
        elif choice == "3":
            HPQ.secureFileByName(path) 
            
        elif choice == "4":
            HPQ.copyToVolume(path, header)
            
        elif choice == "5":
            HPQ.exportFromVolume(path)
            
        elif choice == "6":
            HPQ.deleteFileFromVolume(path)

        elif choice == "0":
            HPQ.encVolume(path, header)
            return
        
        else:
            print("Lựa chọn không hợp lệ. Vui lòng chọn lại.")

def mainmenu():
    while True:
        os.system('cls')
        print("______________ .HPQ VOLUME _______________")
        print("1: Nhập đường dẫn chứa volume để mở volume")
        print("2: Tạo mới volume")
        print("0: Thoát chương trình")

        choice = input("Nhập lựa chọn của bạn: ")

        if choice == "1":
            path = input("Nhập đường dẫn chứa volume: ")
            header = HPQ.readVolume(path)
            HPQ.decVolume(path, header)
            submenu(path, header)

        elif choice == "2":
            path = input("Nhập đường dẫn mới: ")
            header = HPQ.createVolume(path)
            submenu(path, header)

        elif choice == "0":
            print("Thoát chương trình.")
            break  # Kết thúc chương trình nếu người dùng chọn thoát

        else:
            print("Lựa chọn không hợp lệ. Vui lòng chọn lại.")
    
mainmenu()