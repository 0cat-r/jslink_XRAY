
![](https://socialify.git.ci/0cat-r/jslink_XRAY/image?font=KoHo&forks=1&issues=1&language=1&logo=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F49912303%3Fs%3D400%26u%3D0de515f9897d7e5c71b3abb1248273356d981d0e%26v%3D4&owner=1&pattern=Floating%20Cogs&stargazers=1&theme=Dark)



```
     __       .__  .__        __         ____  _____________    _____ _____.___.
    |__| _____|  | |__| ____ |  | __     \   \/  /\______   \  /  _  \\__  |   |
    |  |/  ___/  | |  |/    \|  |/ /      \     /  |       _/ /  /_\  \/   |   |
    |  |\___ \|  |_|  |   |  \    <       /     \  |    |   \/    |    \____   |
/\__|  /____  >____/__|___|  /__|_ \_____/___/\  \ |____|_  /\____|__  / ______|
\______|    \/             \/     \/_____/     \_/        \/         \/\/       
        
    author: 0cat
    version: 1.0
    Github:  https://github.com/0cat-r/jslink_XRAY
````
# jslink_XRAY



##  👮🏻‍免责声明

&emsp;&emsp; 由于传播、利用jslink_XRAY工具（下简称本工具）提供的功能而造成的**任何直接或者间接的后果及损失**，均由使用者本人负责，开发者本人**不为此承担任何责任**。



&emsp;&emsp; 请在使用本工具时遵循使用者以及目标系统所在国当地的**相关法律法规**，一切**未授权测试均是不被允许的**。若出现相关违法行为，我们将**保留追究**您法律责任的权利，并**全力配合**相关机构展开调查。




## :dragon:介绍
&emsp;&emsp; 灵感来自[TimWhitle](https://github.com/timwhitez)的crawlergo_x_XRAY项目，js文件中又经常有一些url接口等，于是就想将这些信息分离出来，并依次交给xray做扫描处理。那么从js中提取一些信息的项目我也有看很多比如jsfinder，jsinfo，linkfinder等等
最后我选择了针对linkfinder进行围绕我的想法进行修改（同时解决了linkfinder无法在win下使用的bug），这才有了本项目中的jslink.py。

&emsp;&emsp; jslink.py将从网站的js中提取接口和url，jslink_Xray.py将结果用request去发到已经启动被动监听的xray中，再由xray进行扫描。
&emsp;&emsp; 建议在windows平台使用。

-----
已经2023年了，写这个脚本的时候rad还没出来，现在大家可以使用更方便，兼容性更高的rad + xray的方案了哦。我这个烂脚本已经积灰很久了

---



## :zap: Installation

&emsp;&emsp; pip3 install -r requirements.txt  

---

## :clap: 用法
&emsp;&emsp; 1.下载最新的已经编译好的[Xray](https://github.com/chaitin/xray/)，并启动被动监听 
xray_windows_amd64.exe webscan --listen 127.0.0.1:7777 --html-output xray-testphp.html 

![在这里插入图片描述](https://raw.githubusercontent.com/0cat-r/jslink_XRAY/main/img/1.png)
![在这里插入图片描述](https://raw.githubusercontent.com/0cat-r/jslink_XRAY/main/img/4.png)

&emsp;&emsp; 2.一行一行将目标站点写入targets.txt中（需要带http/https），output.txt是目标站点js分析出的url和接口
![在这里插入图片描述](https://raw.githubusercontent.com/0cat-r/jslink_XRAY/main/img/3.png)

&emsp;&emsp; 3.修改jslink_Xray.py中的python3环境的路径，修改为自己电脑的python3绝对路径
![在这里插入图片描述](https://raw.githubusercontent.com/0cat-r/jslink_XRAY/main/img/2.png)

&emsp;&emsp; 4.python3 运行jslink_Xray.py

&emsp;&emsp; 5.结果说明：output.txt是目标网站js中的接口和url，漏洞报告在自己本地xray的目录下

---

----
## 📝致谢！

感谢TimWhite，lmy1769779790 帮我答疑解惑

----

## :book: References

* https://github.com/timwhitez/crawlergo_x_XRAY

* https://github.com/GerbenJavado/LinkFinder


## Stargazers over time

[![Stargazers over time](https://starchart.cc/0cat-r/jslink_XRAY.svg)](https://starchart.cc/0cat-r/jslink_XRAY)



