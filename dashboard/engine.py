import hashlib
import os
import time

class Engine:
    def __init__(self, typeH):
        if typeH.lower() == "sha256":
            with open("dashboard/src/DataBase/HashDataBase/Sha256/virusHash.txt", "r") as i:
                self.hashList = i.readlines()
                i.close()

    def hashToFullNum(self, hash_str):
        alpha = 'abcdefghijklmnopqrstuvwxyz'
        alphaNum = {char: idx+1 for idx, char in enumerate(alpha)}
        j = ''
        
        for char in hash_str.lower():
            j += str(alphaNum.get(char, char))
            
        return int(j)

    def binaryTreeSearch(self, hList, valueToFind):
        left = 0
        right = len(hList) - 1
        position = None
        
        while left <= right:
            mid = (left + right) // 2
            if hList[mid] == valueToFind:
                position = mid
                break
            elif hList[mid] < valueToFind:
                left = mid + 1
            else:
                right = mid - 1
                
        return position

    def sha256_hash(self, filename):
        try:
            with open(filename, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            print(f"Error calculating SHA256 for {filename}: {str(e)}")
            return "0"

    def virusScannerSha256(self, path, scan_callback=None):
        self.virusPath = []
        self.virusHashCyPy = []
        ioList = [self.hashToFullNum(h) for h in self.hashList]
        ioList.sort()

        dir_list = []
        for root, _, files in os.walk(path):
            dir_list.extend(os.path.join(root, file) for file in files)

        for file_path in dir_list:
            try:
                if scan_callback:
                    scan_callback(file_path)
                    
                file_hash = self.sha256_hash(file_path)
                hash_num = self.hashToFullNum(file_hash)
                vIHash = self.binaryTreeSearch(ioList, hash_num)
                
                if vIHash is not None:
                    self.virusHashCyPy.append(vIHash)
                    self.virusPath.append(file_path)
            except Exception as e:
                continue

        return self.virusHashCyPy, self.virusPath

        
    def CacheFileRemover(self, callback=None):
        temp_list = []
        username = os.environ.get('USERNAME', '').upper().split(" ")[0]

        directories = [
            "C:/Windows/Temp",
            f"C:/Users/{username}~1/AppData/Local/Temp",
            "C:/Windows/Prefetch"
        ]

        for directory in directories:
            try:
                for root, dirs, files in os.walk(directory):
                    temp_list.extend(os.path.join(root, item) for item in dirs + files)
            except Exception as e:
                continue

        removed_count = 0
        for path in temp_list:
            try:
                if callback:
                    callback(f"Removing: {path}")

                if os.path.isfile(path):
                    os.remove(path)
                    removed_count += 1
                elif os.path.isdir(path):
                    os.rmdir(path)
                    removed_count += 1
            except Exception as e:
                continue

        if callback:
            callback("Junk Cleanup Complete")

        return removed_count


    def FlowDetectorIo(self, path, bit_size):
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        flow_path = os.path.join(base_path, "Database", "Flow Detection", "flow_exe.unibit")
        
        try:
            with open(flow_path, "r") as rFile:
                io_patterns = [line.strip() for line in rFile.readlines()]
                
            with open(path, "rb") as targetFile:
                file_bytes = list(targetFile.read())
                
            byte_str = ''.join(str(byte) for byte in file_bytes)
            match_count = 0
            
            for pattern in io_patterns:
                for i in range(0, len(pattern), bit_size):
                    segment = pattern[i:i+bit_size]
                    if segment in byte_str:
                        match_count += 1
                        
            if len(io_patterns) > 0:
                return (match_count / (len(io_patterns) * (len(pattern)//bit_size))) * 100
            return 0
            
        except Exception as e:
            print(f"Flow detection error: {str(e)}")
            return 0