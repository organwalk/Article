# 基于Docker的Nginx下Vue3及SpringBoot3前后端分离快速云端部署

本文档基于腾讯云轻量应用服务器，所用实例为Linux Ubuntu20.04

## Vue的生产部署

### 打包项目

以使用Vue Cli脚手架为例，在终端中输入`npm run build`命令可构建项目，得到dist目录：

[![image.png](https://i.postimg.cc/13LpBx7P/image.png)](https://postimg.cc/18rnRdZY)

该目录即为需要部署到Nginx的Vue项目。在打包前，需要注意的是：

- 拥有SSL证书(下文会展示如何安装)，应该使用https协议：

  ```js
  return axios.get('https://www.example.com/api/article')
  ```

- 若暂无域名可用公网IP代替，并指定您的后端程序端口；

- 如果您的Springboot项目没有使用`@CrossOrigin`注解，则需自行在Vue项目中配置跨域请求：

  > 一个简单的示例：
  >
  > ```javascript
  > axios.get('http://example.com/api/data', {
  >   withCredentials: true // 携带跨域请求中的cookie信息
  > })
  > .then(response => {
  >   console.log(response.data);
  > })
  > .catch(error => {
  >   console.log(error);
  > });
  > ```
  >
  > 在上面的代码中，设置`withCredentials`为`true`可以让axios在发送跨域请求时携带跨域请求中的cookie信息。
  >
  > 另外，如果你使用的是Vue CLI创建的项目，你可以在`vue.config.js`文件中配置跨域请求。例如，下面的代码将所有以`/api`开头的请求代理到`http://example.com`：
  >
  > ```javascript
  > module.exports = {
  >   devServer: {
  >     proxy: {
  >       '/api': {
  >         target: 'http://example.com',
  >         changeOrigin: true,
  >         pathRewrite: {
  >           '^/api': ''
  >         }
  >       }
  >     }
  >   }
  > };
  > ```
  >
  > 在上面的代码中，`changeOrigin`设置为`true`可以让代理服务器在发送跨域请求时修改`Host`请求头，而`pathRewrite`可以修改请求路径。请注意，跨域请求可能会遇到一些安全问题，例如CSRF攻击，你需要采取一些措施来防止这些安全问题。

### 使用FTP服务上传文件

Vsftpd（very secure FTP daemon）是众多 Linux 发行版中默认的 FTP 服务器。

**安装vsftpd**

```
sudo apt install vsftpd
```

**设置 vsftpd 开机自启动**

```
sudo systemctl enable vsftpd
```

**启动 FTP 服务**

```
sudo systemctl start vsftpd
```

**查看监听端口（默认21端口）**

```
netstat -tlnp
```

若能看见21端口，则表示vsftpd 已默认开启匿名访问模式，无需通过用户名和密码即可登录 FTP 服务器。使用此方式登录 FTP 服务器的用户没有权限修改或上传文件的权限。

**为 FTP 服务创建用户，以 ftpuser 为例**

```
sudo useradd ftpuser
```

**设置 ftpuser 用户的密码**

```
sudo passwd ftpuser
```

输入密码后请按 **Enter** 确认设置，密码默认不显示（**请设置复杂密码，以避免被暴力破解**）

**创建 FTP 服务使用的文件目录，本文以 `/home/user/blog` 为例**

```
sudo mkdir -p /home/user/blog
```

**修改目录权限**

```
sudo chown -R ftpuser:ftpuser /home/user/blog
```

**打开 `vsftpd.conf` 文件**

```
sudo nano /etc/vsftpd/vsftpd.conf
```

**设置匿名用户和本地用户的登录权限，设置指定例外用户列表文件的路径，并开启监听 IPv4 sockets**

```
# 禁用匿名FTP访问
anonymous_enable=NO
# 允许本地用户登录
local_enable=YES
# 将用户锁定在其主目录中，防止访问系统的其他部分
chroot_local_user=YES
# 启用chroot_list文件，用于指定被锁定在主目录中的用户列表
chroot_list_enable=YES
# 指定chroot_list文件的路径
chroot_list_file=/etc/vsftpd/chroot_list
# 启用FTP监听
listen=YES
```

**在行首添加 `#`，注释 `listen_ipv6=YES` 配置参数，关闭监听 IPv6 sockets**

```
#listen_ipv6=YES
```

**添加以下配置参数，开启被动模式，设置本地用户登录后所在目录，以及云服务器建立数据传输可使用的端口范围值**

```
# 指定FTP用户的主目录为/home/user/blog
local_root=/home/user/blog

# 允许用户在chroot环境下写入文件
allow_writeable_chroot=YES

# 启用被动模式（PASV）
pasv_enable=YES

# 指定被动模式（PASV）的监听地址为轻量应用服务器公网 IP
pasv_address=xxx.xx.xxx.xx  # 请修改为您的轻量应用服务器公网 IP

# 指定被动模式（PASV）使用的端口范围
pasv_min_port=40000
pasv_max_port=45000
```

编辑完成后保存并退出

**重启 FTP 服务**

```
sudo systemctl restart vsftpd
```

**设置安全组策略**

您应该在服务器的防火墙安全组策略中开放21端口

**更优雅地使用FTP服务**

使用xftp可在图形化界面下便捷地将Windows下文件拖拽上传至服务器中，您可在官网申请免费许可证以使用xftp：

![image.png](https://www.xshell.com/wp-content/uploads/2020/11/p-xftp7-main-zh-800x436.png)

链接：[家庭/学校免费 - NetSarang Website (xshell.com)](https://www.xshell.com/zh/free-for-home-school/)

在安全组策略中开放22端口以实现Linux SSH登录，然后将dist目录上传至/home/user/blog目录中

### 安装Nginx

Nginx是一种高性能的Web服务器和反向代理服务器，它具有以下特点和用途：

1. 高性能和可伸缩性：Nginx具有高效的事件驱动架构，能够处理大量的并发请求，并能够水平扩展以适应高流量负载。

2. 反向代理和负载均衡：Nginx作为反向代理服务器可以将来自客户端的请求转发到多个后端应用服务器上，从而实现负载均衡和高可用性。

3. 静态内容服务：Nginx可以作为一个高效的静态文件服务器，提供静态文件的高速传输，减轻后端应用服务器的负载。

4. 安全性和可靠性：Nginx具有丰富的安全和可靠性特性，如SSL/TLS支持、基于IP的访问控制、请求限速、缓存控制等。

5. 可扩展性：Nginx支持多种模块和插件，可以扩展其功能和性能。

**进入目录`/home/user/blog`**

```
cd /home/user/blog
```

**在该目录中创建一个名为`nginx.conf`的文件**

该文件将作为Nginx的自定义配置文件

```
touch nginx.conf
```

**使用nano编辑器打开`nginx.conf`文件**

```
nano nginx.conf
```

**编写基本的配置文件**

```
server {
    listen 80;
    server_name localhost;#填写公网IP或域名

    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

**在docker中安装Nginx镜像（请确保您安装了docker）**

```
docker pull nginx
```

**启动一个新的 `blogow` 容器，并将其映射到主机的80和443端口**

```
docker run --name blogow -p 80:80 -p 443:443 -v /home/user/blog/dist:/usr/share/nginx/html -v /home/user/blog:/etc/nginx/conf.d -d nginx
```

这将会启动一个新的Nginx容器，名称为 `blogow`（可自定义），并将主机的80和443端口映射到容器的80和443端口（应该在安全组策略开放这两个端口）上。同时，它会将主机上的 `/home/user/blog/dist` 目录挂载到容器内的 `/usr/share/nginx/html` 目录，并将主机上的 `/home/user/blog` 目录挂载到容器内的 `/etc/nginx/conf.d` 目录上。

**确认新的容器已经在运行**

```
sudo docker ps
```

检查该容器是否正在运行

**（可选）查看运行日志**

```
sudo docker logs blogow
```

有时由于您的操作不当，可能会导致Nginx容器运行失败。可凭借此查看该容器的运行状况及出错原因

### SSL证书安装

下载您所拥有的SSL证书的Nginx类型版本：

[![image.png](https://i.postimg.cc/sgW6qpGb/image.png)](https://postimg.cc/75xnTJVN)

将下载好的压缩包打开，并且将其中的`.crt`后缀文件和`.key`后缀文件上传至/home/user/blog目录下

**拷贝SSL证书文件至Nginx容器中**

以本网站为例：

```
sudo docker cp /home/user/blog/organwalk.ink.key blogow:/usr/share/nginx
sudo docker cp /home/user/blog/organwalk.ink_bundle.crt blogow:/usr/share/nginx
```

### 使用Nginx配置SSL证书

```
server {
	# 监听80和443端口，并启用SSL
    listen 80;
    listen 443 ssl;
    server_name organwalk.ink;

    # 指定SSL证书和私钥的路径
    ssl_certificate /usr/share/nginx/organwalk.ink_bundle.crt;
    ssl_certificate_key /usr/share/nginx/organwalk.ink.key;

    # 固定写法
    server_tokens off;# 禁用HTTP响应中的服务器版本信息
    ssl_session_timeout 5m;# 配置SSL会话超时时间
    ssl_protocols TLSv1.2 TLSv1.3;# 指定SSL协议的版本
    # 指定SSL加密套件的优先级和具体算法
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;   
    ssl_prefer_server_ciphers on;# 优先使用服务器端的加密算法
    
    # 配置根目录和默认首页
    location / {
        root /usr/share/nginx/html;
        index index.html;

        # 配置URL重写规则，解决Vue的重定向问题
        try_files $uri $uri/ /index.html;
    }

    # 如果访问的是非HTTPS页面，则重定向到HTTPS页面
    if ($scheme != "https") {
        return 301 https://$server_name$request_uri;
    }
}
```

**停止当前的Nginx容器**

```
sudo docker stop blogow
```

**启动当前的Nginx容器**

```
sudo docker start blogow
```

至此已将Vue项目部署完毕

## SpringBoot的生产部署

**注：Docker Hub中只有openjdk镜像可供下载，截止于2023年04月16日，最新版本为18，因此您项目的openjdk版本应低于18。**

将Maven树中打包好的jar包上传至/home/user/blog目录下，并重命名为`app.jar`

### 创建并运行项目容器

```
sudo docker run -d -p 8081:8081 -v /home/user/blog/app.jar:/app.jar --name organwalk openjdk java -jar /app.jar --server.port=8081
```

您应该将容器映射端口修改为与您项目相符合的端口。该命令将创建一个名为organwalk的容器，同时在后台运行。您可以通过`sudo docker ps`命令查看其运行情况。

### 使用Nginx反向代理后端请求

Nginx作为反向代理服务器时，其工作原理如下：

1. 客户端发送请求到Nginx反向代理服务器。
2. Nginx反向代理服务器接收到请求，并根据配置文件中的规则将请求转发到后端服务器。
3. 后端服务器接收到请求，并返回响应给Nginx反向代理服务器。
4. Nginx反向代理服务器接收到响应，并将响应返回给客户端。

反向代理服务器隐藏了后端服务器的真实IP地址和端口号，并将客户端的请求转发到后端服务器，从而实现了负载均衡和高可用性。此外，Nginx反向代理服务器还可以对请求进行缓存、限速、访问控制等操作，以提高性能和安全性。

在原有的配置文件基础上，反向代理所有以`/api`开头的请求

```
server {
	# 监听80和443端口，并启用SSL
    listen 80;
    listen 443 ssl;
    server_name organwalk.ink;

    # 指定SSL证书和私钥的路径
    ssl_certificate /usr/share/nginx/organwalk.ink_bundle.crt;
    ssl_certificate_key /usr/share/nginx/organwalk.ink.key;

    # 固定写法
    server_tokens off;# 禁用HTTP响应中的服务器版本信息
    ssl_session_timeout 5m;# 配置SSL会话超时时间
    ssl_protocols TLSv1.2 TLSv1.3;# 指定SSL协议的版本
    # 指定SSL加密套件的优先级和具体算法
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;   
    ssl_prefer_server_ciphers on;# 优先使用服务器端的加密算法
    
    location /api/ {
        proxy_pass http://www.organwalk.ink:8081/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    
    # 配置根目录和默认首页
    location / {
        root /usr/share/nginx/html;
        index index.html;

        # 配置URL重写规则，解决Vue的重定向问题
        try_files $uri $uri/ /index.html;
    }

    # 如果访问的是非HTTPS页面，则重定向到HTTPS页面
    if ($scheme != "https") {
        return 301 https://$server_name$request_uri;
    }
}
```

Nginx代理请求头部指令的作用如下：

1. proxy_set_header Host $host;：该指令设置代理请求头部中的Host字段，用于指定请求的目标服务器。$host变量会自动获取客户端请求中的Host字段，确保请求的正确传递。
2. proxy_set_header X-Real-IP $remote_addr;：该指令设置代理请求头部中的X-Real-IP字段，用于指定客户端的真实IP地址。$remote_addr变量会自动获取客户端的IP地址，防止使用代理服务器的假IP地址。
3. proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;：该指令设置代理请求头部中的X-Forwarded-For字段，用于指定客户端的IP地址和代理服务器的IP地址。$proxy_add_x_forwarded_for变量会自动添加客户端的IP地址和代理服务器的IP地址，以便于后端服务器识别请求来源。

您还可以使用Nginx实现跨域请求：

```
add_header 'Access-Control-Allow-Origin' '*';
add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS';
add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range';
```

当您写好配置文件，保存并退出后，执行如下操作：

**停止当前的Nginx容器**

```
sudo docker stop blogow
```

**启动当前的Nginx容器**

```
sudo docker start blogow
```



## 结尾

至此，基于Docker的Nginx下Vue3及SpringBoot3前后端分离快速云端部署已顺利完成。您还可以通过编写`Dockerfile`和`Docker Compose`文件满足您对项目部署进行精细化及具有可拓展性的管理的需求。

### 附录

**基于Vue CLI的Docker（Nginx）生产部署：**

[部署 | Vue CLI (vuejs.org)](https://cli.vuejs.org/zh/guide/deployment.html#docker-nginx)

**OpenJDK镜像：**

https://hub.docker.com/_/openjdk

**DockerCompose：**

https://docs.docker.com/compose/