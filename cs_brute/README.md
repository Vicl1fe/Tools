# CS_Brute

根据网上公开的CS密码爆破脚本，自己修改了一下增加了批量检测功能。



**使用方法**

```
python3 cs_brute.py -h
usage: cs_brute.py [-h] [-t THREADS] host wordlist

positional arguments:
  host        IP:PORT/文件
  wordlist    字典文件

optional arguments:
  -h, --help  show this help message and exit
  -t THREADS  线程数量
```

**例子**

```
python3 cs_brute.py host.txt pass.txt
```

url.txt格式例子如下

```
IP:PORT
```



