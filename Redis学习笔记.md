# Redis学习笔记

基于Ubuntu20.04与docker的redis学习。

## 常用配置命令

### 安装docker

```shell
sudo apt-get update
sudo apt-get install docker.io
```

### docker中的redis启动

#### 查看监听端口

```shell
netstat -tlnp
```

#### 查看docker运行状态

```shell
systemctl status docker.service
```

#### 禁用本地redis的6379端口

如果本地安装了redis

```
sudo systemctl stop redis.service
```

### 启用docker及容器

```shell
systemctl start docker
docker container ls -a
docker container start（container Id or name）
```

### 查看特定docker日志

```shell
docker logs （container Id or name）
```

### 删除docker

```
docker rm dockername
```

### 展示所有docker容器

```
docker ps -a
```

### 下载Redis镜像

```
sudo docker pull redis
```

### 创建配置文件

```
mkdir -p /home/user
mkdir redis-data
touch /home/user/redis.conf
nano /home/user/redis.conf
```

### 编辑配置文件

```
bind 0.0.0.0
port 6379
requirepass 123456
appendonly yes
dir /data
daemonize no
```

### 在redis容器中挂载配置文件

```
docker run -d --name redis -p 6379:6379 -v /home/user/redis.conf:/usr/local/etc/redis/redis.conf -v /home/user/redis-data:/data redis redis-server /usr/local/etc/redis/redis.conf
```

### 进入docker中的redis

```
docker exec -it redis /bin/bash
redis-cli
auth 123456
```

### Windows下连接Ubuntu虚拟机内redis容器

如果你在 Windows 主机上安装了虚拟机，并在虚拟机中安装了 Redis 容器，那么你需要使用虚拟机的 IP 地址来连接 Redis 容器。

具体来说，你需要执行以下步骤：

1. 获取虚拟机的 IP 地址

在虚拟机中可以使用以下命令来获取虚拟机的 IP 地址：

- 在 Linux 中，可以使用以下命令：

  ```
  ip addr show
  ```

  这将显示虚拟机的网络配置信息，其中包括虚拟机的 IP 地址。

- 在 Windows 中，可以使用以下命令：

  ```
  ipconfig
  ```

  这将显示虚拟机的网络配置信息，其中包括虚拟机的 IP 地址。

2. 配置 RESP.app

启动 RESP.app，在连接管理器中点击 “+” 按钮添加一个新的连接。在弹出的对话框中，输入以下信息：

- 连接名称：自定义的名称
- 主机：虚拟机的 IP 地址
- 端口：6379
- 密码：如果 Redis 容器设置了密码，需要输入密码

点击 “测试连接” 按钮测试连接是否成功，然后点击 “保存” 按钮保存连接配置。

3. 连接 Redis

在连接管理器中双击新建的连接，如果连接成功，就可以在 RedisDesktopManager 中管理 Redis 数据库了。

需要注意的是，在进行连接时，需要确保虚拟机的防火墙允许连接 Redis 服务的端口，并且 Redis 容器的网络连接是正常的。如果连接失败，可以检查网络设置和防火墙设置是否正确。

### 配置MySQL

#### 设置镜像源

```
mkdir -p /etc/docker
sudo touch /etc/docker/daemon.json
nano /etc/docker/daemon.json
```

#### 在文件中添加镜像源

```json
{
  "registry-mirrors": [
    "https://registry.docker-cn.com",
    "https://docker.mirrors.ustc.edu.cn",
    "https://hub-mirror.c.163.com"
  ]
}
```

#### 重启docker服务

```
sudo systemctl restart docker
```

#### 验证镜像源是否添加成功

```
sudo docker info
```

#### 拉取mysql镜像

```
sudo docker pull mysql
```

#### 创建mysql容器

```
sudo docker run -d --name mysql -p 3306:3306 -e MYSQL_ROOT_PASSWORD=<your_password> mysql
```

#### 连接mysql容器

```
sudo docker exec -it mysql bash
```

#### 在mysql容器中配置mysql

```
mysql -u root -p
```

然后需要输入mysql密码

> 以下步骤可省略，可迁移至navicat图形化操作
> 创建一个数据库
>
> ```mysql
> CREATE DATABASE <your_database_name>;
> ```
>
> 创建一个用户
>
> ```mysql
> CREATE USER '<your_username>'@'%' IDENTIFIED BY '<your_password>';
> ```
>
> 授权用户访问数据库
>
> ```mysql
> GRANT ALL PRIVILEGES ON <your_database_name>.* TO '<your_username>'@'%';
> ```
>
> 

#### 获取docker容器IP

```
sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' <container_name>
```

#### 在navicat配置连接

- 主机名/ IP地址：将linux的IP地址输入到此字段中。
- 端口号：输入3306。
- 用户名：输入您在MySQL容器中创建的用户名。
- 密码：输入您在MySQL容器中创建的密码。
- 数据库：输入您在MySQL容器中创建的数据库名称。

完成后测试连接

## 通过Jedis读写Redis

### 基本使用

#### 添加依赖项：

```xml
<dependency>
	<groupId>redis.clients</groupId>
	<artifactId>jedis</artifactId>
	<version>4.3.2</version>
</dependency>
```

```java
Jedis jedis = new Jedis("192.168.71.236",6379);
jedis.auth("123456");
System.out.println(jedis.ping());
System.out.println(jedis.set("name","张三"));
System.out.println(jedis.get("name"));
System.out.println(jedis.del("name"));
```

### 开启事务

```java
Transaction t1 = jedis.multi();
t1.set("score","90");
t1.set("age","22");
t1.exec();
//jedis.watch();
```

### 配置连接池

```java
JedisPoolConfig config = new JedisPoolConfig();
config.setMaxTotal(10);//最大连接数
config.setMaxIdle(5);//最大空闲连接
config.setMinIdle(3);//最大等待时间
config.setMaxWaitMillis(5000);//连接耗尽时不阻塞
JedisPool pool = new JedisPool(config,"192.168.71.236",6379);
Jedis jedis = pool.getResource();
jedis.auth("123456");
```

### 基于连接池读写

```java
jedis.auth("123456");
jedis.set("name","李四");
System.out.println(jedis.get("name"));

jedis.rpush("arr1","10","20","30");
System.out.println(jedis.lindex("arr1",0));

jedis.hset("user","name","zhangsan");
jedis.hset("user","age","22");
System.out.println(jedis.hget("user","name"));

HashMap map = new HashMap();
map.put("birthday","2010-10-22");
map.put("score","89");
jedis.hset("user",map);

pool.close();
```

## Redis缓存与整合MySQL

### 添加依赖

```xml
<dependency>
	<groupId>com.mysql</groupId>
	<artifactId>mysql-connector-j</artifactId>
	<version>8.0.32</version>
</dependency>
<dependency>
	<groupId>redis.clients</groupId>
	<artifactId>jedis</artifactId>
	<version>4.3.2</version>
</dependency>
```

### 配置MySQL

```java
public class JDBCUtil {
    private static String driver = "com.mysql.cj.jdbc.Driver";
    private static String url = "jdbc:mysql://192.168.71.236/docker_mysql";
    private static String user = "root";
    private static String password = "123456";

    static {
        try {
            Class.forName(driver);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static Connection getConnection() throws SQLException {
        Connection conn = null;
        conn = DriverManager.getConnection(url,user,password);
        return  conn;
    }

    public static void close(Connection conn, PreparedStatement statement, ResultSet resultSet) throws SQLException {
        if (resultSet != null){
            resultSet.close();
        }
        if (statement != null){
            statement.close();
        }
        if (conn != null){
            conn.close();
        }
    }
}
```

### 配置Jedis连接池

```java
public class JedisUtil {
    private static JedisPool pool;
    static {
        JedisPoolConfig config = new JedisPoolConfig();
        config.setMaxTotal(10);//最大连接数
        config.setMaxIdle(5);//最大空闲连接
        config.setMinIdle(3);//最大等待时间
        config.setMaxWaitMillis(5000);//连接耗尽时不阻塞

        pool = new JedisPool(config,"192.168.71.236",6379,5000,"123456");
    }

    public static Jedis getJedis(){
        return pool.getResource();
    }
}
```

### 实体类

```java
public class Product {
    private int id;
    private String name;
    private float price;
    private int category;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public float getPrice() {
        return price;
    }

    public void setPrice(float price) {
        this.price = price;
    }

    public int getCategory() {
        return category;
    }

    public void setCategory(int category) {
        this.category = category;
    }

    @Override
    public String toString() {
        return "Product{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", price=" + price +
                ", category=" + category +
                '}';
    }
}
```

### 缓存与整合MySQL

```java
public class CacheDemo {
    public static void main(String[] args) throws SQLException {
        findByID(1);
    }

    //查询商品
    public static void findByID(int id) throws SQLException {
        //1.查看缓存中是否有数据
        Product product = getByRedis(id);
        if (product == null){
            System.out.println("缓存中未查询到商品");
            product = getByMySQL(id);
            if (product == null){
                System.out.println("MySQL中未查询到商品");
            }else{
                System.out.println("MySQL中查询到数据");
                System.out.println(product);
                saveToRedis(product);
            }
        }else {
            System.out.println("缓存中查询到数据");
            System.out.println(product);
        }
    }

    //存储商品至Redis hash key field value
    public static void saveToRedis(Product product){
        Jedis jedis = JedisUtil.getJedis();
        String key = "product:"+product.getId();
        jedis.hset(key,"name",product.getName()+"");
        jedis.hset(key,"price",product.getPrice()+"");
        jedis.hset(key,"category",product.getCategory()+"");
        //防止内存溢出
        jedis.expire(key,3600);
    }

    //从redis中获取商品
    public static Product getByRedis(int id){
        String key = "product:" + id;
        Jedis jedis = JedisUtil.getJedis();
        Product product = null;
        if (jedis.exists(key)){
            String name = jedis.hget(key,"name");
            float price = Float.parseFloat(jedis.hget(key,"price"));
            int category = Integer.parseInt(jedis.hget(key,"category"));
            product = new Product();
            product.setId(id);
            product.setName(name);
            product.setPrice(price);
            product.setCategory(category);
        }
        return product;
    }

    //根据ID从MySQL中查询数据
    public static Product getByMySQL(int id) throws SQLException {
        Connection conn = JDBCUtil.getConnection();
        String sql = "select * from product where id = ?";
        PreparedStatement statement = conn.prepareStatement(sql);
        statement.setInt(1,id);
        ResultSet resultSet = statement.executeQuery();
        Product product = null;
        while (resultSet.next()){
            String name = resultSet.getString("name");
            float price = resultSet.getFloat("price");
            int category = resultSet.getInt("category");
            product = new Product();
            product.setId(id);
            product.setName(name);
            product.setPrice(price);
            product.setCategory(category);
        }
        JDBCUtil.close(conn,statement,resultSet);
        return product;
    }
}
```

## Redis缓存优化

### 缓存穿透

#### 恶意查询

```java
public static void main(String[] args) throws SQLException {
        for (int i = 0; i<10;i++){
            findByID(-1);
        }
}
```

#### 缓存不存在的键

```java
public static void findByID(int id) throws SQLException {
        //1.查看缓存中是否有数据
        Product product = getByRedis(id);
        if (product == null){
            System.out.println("缓存中未查询到商品");
            product = getByMySQL(id);
            if (product == null){
                System.out.println("MySQL中未查询到商品");
                //将空数据存储至redis，对象中没有属性值
                Product p = new Product();
                p.setId(id);
                //如果仍然恶意查询，则可返回该空键
                saveToRedis(p);
            }else{
                System.out.println("MySQL中查询到数据");
                System.out.println(product);
                saveToRedis(product);
            }
        }else {
            System.out.println("缓存中查询到数据");
            System.out.println(product);
        }
}
```

### 缓存雪崩

指在同一时段大量的缓存key同时失效或者Redis服务宕机，导致大量请求到达数据库，带来巨大压力。解决方案：

- 给不同的Key的TTL添加随机值
- 利用Redis集群提高服务的可用性

```java
public static void saveToRedis(Product product){
        Jedis jedis = JedisUtil.getJedis();
        String key = "product:"+product.getId();
        jedis.hset(key,"name",product.getName()+"");
        jedis.hset(key,"price",product.getPrice()+"");
        jedis.hset(key,"category",product.getCategory()+"");
        int expiredTime = 3600 + new Random().nextInt(100);
        jedis.expire(key,expiredTime);
}
```

该代码中通过设置随机过期时间来避免缓存同时失效，从而减轻了缓存雪崩的压力。

> 但是，该代码仍然存在以下问题：
>
> 1. 如果该产品的缓存在同一时刻被大量请求，仍然会造成缓存雪崩的问题。
> 2. 如果缓存中的数据存在更新，但没有及时更新缓存，则会导致缓存中的旧数据被访问，从而影响系统性能。
>
> 因此，为了更好地解决缓存雪崩问题，可以采取以下措施：
>
> 1. 对于热点数据，采用分布式锁或队列等方式来限制对数据库的并发访问，从而避免并发请求同时访问数据库。
> 2. 使用多级缓存策略，例如将缓存数据分为多个层级，不同层级的缓存设置不同的过期时间，从而降低缓存同时失效的概率。同时，可以使用缓存预热等方式来提前加载缓存数据，从而避免缓存冷启动的问题。
> 3. 对于缓存更新，可以采用缓存穿透和缓存击穿解决方案，例如使用布隆过滤器来过滤无效请求，使用缓存更新策略来保证缓存数据的实时性。

## Redis限流

Redis限流是指使用Redis实现对访问频率的控制，通过限制单位时间内的请求次数，从而保护系统不被过多的请求压垮，以提高系统的可用性和稳定性。

```java
public class LimitUtil {
    public static void canVisit(Jedis jedis,String requestType,int limitTime,int limitCount){
        // 获取当前时间戳
        long currentTime = System.currentTimeMillis();
        // 将当前时间戳作为分值，添加到有序集合中，并以当前时间戳作为成员
        jedis.zadd(requestType, currentTime, currentTime + "");
        // 移除有序集合中分值小于等于 (当前时间戳 - 时间窗口大小) 的成员
        jedis.zremrangeByScore(requestType, 0, currentTime - limitTime * 1000);
        // 获取有序集合中成员的数量，即窗口时间内的请求总数
        long count = jedis.zcard(requestType);
        // 设置有序集合的过期时间为 (时间窗口大小 + 1)，防止过期时出现数据不一致的情况
        jedis.expire(requestType, limitTime + 1);
        // 判断当前请求总数是否小于等于限制的请求数，返回限流结果
        boolean flag = count <= limitCount;
        if (flag) {
            System.out.println("允许访问");
        } else {
            System.out.println("限制访问");
        }
    }

    public static void main(String[] args) {
        Jedis jedis = JedisUtil.getJedis();
        jedis.del("测试请求");
        //模拟发送
        for (int i = 0;i < 5;i++){
            LimitUtil.canVisit(jedis,"测试请求",100,3);
        }
    }
}
```

这段代码的实现原理就像是一把门禁，只允许在一定时间内通过一定数量的人进入某个场所，超出限制的人则需要等待或被拒绝进入。

具体来说，这把门禁使用了Redis的有序集合作为记录器，每个人进入场所时，相当于在有序集合中添加了一个记录，记录的分值是当前时间戳，成员是当前时间戳的字符串形式。这里有序集合的好处是可以方便地对记录进行排序和移除。

同时，为了控制人数和时间，这把门禁还设置了两个参数：限制时间窗口大小（limitTime）和限制人数（limitCount）。在每个人进入场所时，这把门禁会先将记录中时间窗口之前的记录移除，只保留时间窗口内的记录，然后再计算当前记录的数量，判断是否超出了限制人数，如果超出了，则不允许进入，否则允许进入。

> 可以把这个限流的过程想象成一个门口，门口上有一个计数器和一个时钟。门口有一个限制人数（limitCount）和限制时间窗口大小（limitTime），比如说限制人数是10人，限制时间窗口大小是1分钟。
>
> 每当有一个人要进入门口时，门口的计数器就会加1，并且记录下当前的时间。如果此时门口内的人数超过了限制人数，那么门口就会拒绝后续的人进入，直到有人离开门口，使得门口内的人数小于等于限制人数。
>
> 同时，为了避免记录一直增长，门口上还设置了一个时钟，每隔一段时间（比如说1分钟），门口就会自动清除过期的记录，并将计数器归零，重新开始计数。

最后，为了避免记录一直增长，这把门禁还设置了过期时间，超时后会自动清除记录。

因此，这段代码的实现原理就是通过Redis有序集合来记录请求的时间戳，并在一定时间窗口内限制请求的数量，从而保护系统不被过多的请求压垮，就像一把门禁限制了进入场所的人数和时间一样。

## Redis整合MySQL集群

在MySQL主从集群中，主节点就是负责管理数据库的主要决策者，从节点则是主节点的辅助力量，可以帮助主节点处理一些日常事务。**我们通常通过主节点进行写入操作，从节点进行读取操作。**通过将数据库的读写操作分散到多个节点上，可以大幅提高数据库的并发处理能力，提高系统的稳定性和性能。

### MySQL的二进制日志机制

主节点和从节点之间的数据同步，通常采用Mysql的二进制日志（binlog）机制。主节点将自己的操作记录在binlog中，从节点通过读取主节点的binlog，来进行数据同步。

具体来说，当主节点发生更新操作时，会将操作记录在binlog中，并将binlog的数据发送给从节点。从节点接收到binlog数据后，就会解析binlog，将更新操作应用到自己的数据库中，从而保证从节点的数据与主节点保持一致。

除了binlog机制，Mysql主从集群还支持其他的同步机制，比如基于GTID的复制、半同步复制等等。这些机制的原理和实现方式都有所不同，但都是为了实现主节点和从节点之间的数据同步，确保从节点的数据与主节点保持一致。

需要注意的是，Mysql主从集群的数据同步过程中，由于网络、硬件等原因，可能会出现延迟或者丢失的情况。因此，在使用Mysql主从集群时，需要根据实际情况进行配置和优化，确保数据同步的及时性和准确性。

### 主从切换

如果Mysql主节点出现故障，从节点会自动接管。

在Mysql主从集群中，主节点负责处理写操作，从节点负责处理读操作。当主节点出现故障时，从节点会检测到主节点的状态变化，并尝试自动接管主节点的角色，成为新的主节点，继续处理写操作和读操作。

当从节点成为新的主节点后，其他从节点会自动切换到新的主节点上，继续处理读操作。这个过程称为主从切换（Master-Slave Switch），是Mysql主从集群中实现高可用性的核心机制之一。

需要注意的是，主节点出现故障后，从节点自动接管的过程需要一定的时间，期间可能会出现短暂的服务中断。为了最大程度地减少服务中断的时间，通常会采用一些技术手段，比如使用Mysql高可用性解决方案中的VIP（Virtual IP）技术，将主节点和从节点绑定在同一个虚拟IP上，以实现快速的主从切换和故障恢复。

### 在Docker中配置MySQL集群

#### 创建Docker Compose文件

```
mkdir my-docker-project
mkdir -p master/data
chmod -R 777 master/data
cd my-docker-project
touch docker-compose.yml
nano docker-compose.yml
```

修改以下内容部分参数并复制其中：

```yml
version: '3'

services:
  master:
    container_name: mysql-master
    image: mysql:8.0.32
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: 123456
      MYSQL_DATABASE: master-database
      MYSQL_USER: user-master
      MYSQL_PASSWORD: 123456
    volumes:
      - ./master/data:/var/lib/mysql
    ports:
      - "3306:3306"
    networks:
      - cluster

  slave1:
    container_name: mysql-slave1
    image: mysql:8.0.32
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: 123456
      MYSQL_DATABASE: slave1-database
      MYSQL_USER: user-slave1
      MYSQL_PASSWORD: 123456
      MYSQL_MASTER_HOST: master
      MYSQL_MASTER_PORT: 3306
      MYSQL_REPLICA_USER: slave1
      MYSQL_REPLICA_PASSWORD: 123456
    volumes:
      - ./slave1/data:/var/lib/mysql
    networks:
      - cluster

  slave2:
    container_name: mysql-slave2
    image: mysql:8.0.32
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: 123456
      MYSQL_DATABASE: slave2-database
      MYSQL_USER: user-slave2
      MYSQL_PASSWORD: 123456
      MYSQL_MASTER_HOST: master
      MYSQL_MASTER_PORT: 3306
      MYSQL_REPLICA_USER: slave2
	  MYSQL_REPLICA_PASSWORD: 123456
    volumes:
      - ./slave2/data:/var/lib/mysql
    networks:
      - cluster

networks:
  cluster:

```

#### 创建Docker网络

```
docker network create cluster
```

#### 启动 Docker Compose

```
apt install docker-compose
```

进入包含docker-compose.yml文件的目录。运行以下命令启动Docker Compose：

```
docker-compose up -d
```

#### 配置主节点

在主节点上，使用以下命令登录MySQL：

```
docker exec -it mysql-master mysql -p
```

一旦登录，则创建一个新的用户并分配复制权限。例如，创建一个名为muser的用户，并授予该用户从主节点读取binlog的权限：

```
CREATE USER 'muser'@'%' IDENTIFIED WITH mysql_native_password BY '123456';
GRANT REPLICATION SLAVE ON *.* TO 'muser'@'%';
FLUSH PRIVILEGES;
```

然后，执行以下命令查看主节点的状态：

```
SHOW MASTER STATUS;
```

记下File和Position值，这些值将用于配置从节点。

#### 配置从节点

在从节点上，使用以下命令登录MySQL：

```
docker exec -it mysql-slave1 mysql -p
```

登录后删除从节点有，但主节点无的数据库。

然后执行以下命令配置从节点（注意`MASTER_LOG_FILE`和`MASTER_LOG_POS`）：

```mysql
CHANGE MASTER TO MASTER_HOST='master', MASTER_PORT=3306, MASTER_USER='muser', MASTER_PASSWORD='123456', MASTER_LOG_FILE='binlog.000001', MASTER_LOG_POS=157;
START SLAVE;
```

执行该命令以查看主从连接状态：

```
SHOW SLAVE STATUS\G
```

在输出中，您需要查看以下字段的值：

- `Slave_IO_Running`: 如果该值为`Yes`，则表示从节点的I/O线程正在运行，正在从主节点读取二进制日志文件。
- `Slave_SQL_Running`: 如果该值为`Yes`，则表示从节点的SQL线程正在运行，正在将读取的二进制日志应用于从节点上的数据库。
- `Last_Error`: 如果该值不为`NULL`，则表示复制进程遇到了错误。您可以查看该字段的值，以获取有关错误的更多详细信息。

重复该步骤配置mysql-slave2

#### 验证主从复制

在主节点上，创建一个新的数据库和表，并将一些数据插入该表中：

```mysql
CREATE DATABASE test;
USE test;
CREATE TABLE users (id INT, name VARCHAR(255));
INSERT INTO users (id, name) VALUES (1, 'Alice'), (2, 'Bob');
```

在从节点上，查询该表的内容：

```mysql
USE test;
SELECT * FROM users;
```

#### 测试故障转移

关闭主节点容器以模拟故障：

```
docker stop mysql-master
```

等待片刻，然后在从节点上查询该表的内容：

```
USE test;
SELECT * FROM users;
```

您应该能看到从第二个从节点（mysql-slave2）中获取的数据，因为它已经成为了新的主节点。您可以使用以下命令将第二个从节点（mysql-slave2）设置为新的主节点：

```
STOP SLAVE;
RESET MASTER;
```

然后，重新启动主节点容器：

```
docker start mysql-master
```

### 使用 JDBC 读写主从库

#### 改写JDBCUtil类

```java
private static String masterUrl = "jdbc:mysql://192.168.71.236:3306/mtest?useUnicode=true&characterEncoding=utf-8&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC";
private static String slaveUrl = "jdbc:mysql://192.168.71.236:3306/mtest?useUnicode=true&characterEncoding=utf-8&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC&readFromMasterWhenNoSlaves=false";

public static Connection getConnection(boolean isWrite) throws SQLException {
        String url = isWrite ? masterUrl :slaveUrl;
        Connection conn = null;
        conn = DriverManager.getConnection(url,user,password);
        return  conn;
}
```

#### 从库读取

```java
//根据ID从MySQL中查询数据
public static Product getByMySQL(int id) throws SQLException {
        Connection conn = JDBCUtil.getConnection(false);
        String sql = "select * from product where id = ?";
        PreparedStatement statement = conn.prepareStatement(sql);
        statement.setInt(1,id);
        ResultSet resultSet = statement.executeQuery();
        Product product = null;
        while (resultSet.next()){
            String name = resultSet.getString("name");
            float price = resultSet.getFloat("price");
            int category = resultSet.getInt("category");
            product = new Product();
            product.setId(id);
            product.setName(name);
            product.setPrice(price);
            product.setCategory(category);
        }
        JDBCUtil.close(conn,statement,resultSet);
        return product;
}
```

#### 主库写入

```java
public class MySQLTest {
    public static void main(String[] args) throws SQLException {
        insert();
    }
    public static void insert() throws SQLException {
        Connection conn = JDBCUtil.getConnection(true);
        String sql = "insert into product(name,price,category)values(?,?,?)";
        PreparedStatement statement = conn.prepareStatement(sql);
        statement.setString(1,"test");
        statement.setFloat(2,2000);
        statement.setInt(3,40);
        int r = statement.executeUpdate();
        System.out.println(r);
        JDBCUtil.close(conn,statement,null);
    }
}
```

## Lua脚本

Lua脚本是一种用Lua语言编写的脚本，通常用于嵌入式系统、游戏开发、Web应用程序、科学计算、网络编程等领域。在Redis中引入Lua脚本是为了实现复杂的操作，提高Redis的性能和灵活性。

Redis是一种内存数据库，数据存储在内存中，因此它的性能非常高。Redis可以支持各种数据结构，如字符串、哈希、列表、集合等，并提供了各种操作这些数据结构的命令。然而，有些操作需要执行多个Redis命令才能完成，这可能会导致性能问题，因为每个Redis命令都需要进行网络通信和数据传输。

为了避免这种性能问题，Redis引入了Lua脚本。Lua脚本可以在Redis服务器端执行，由于脚本是在服务器端执行，因此可以减少网络通信和数据传输，提高Redis的性能。此外，Lua脚本还可以批量操作数据，减少了Redis命令的调用次数，进一步提高了Redis的性能。

除了性能方面的优势，Lua脚本还可以实现复杂的操作，如事务、锁、队列等。Lua脚本提供了一种灵活的方式，可以在Redis中实现各种高级功能，同时保持Redis简单和易于使用的特点。

#### Java调用Lua脚本

在Java中，可以使用Jedis客户端库来连接Redis服务器并执行Lua脚本。Jedis库已经提供了相关的API，无需手动编写Lua脚本文件并复制到Redis容器中。

```java
public class LimitByLuaUtil {
    private static String script = "local obj =KEYS[1]\n" +  //定义obj变量为传入的key值
            "local limitNum = tonumber(ARGV[1])\n" +  //定义limitNum变量为传入的限制次数
            "local curVisitNum = tonumber(redis.call('get',obj) or '0')\n" +  //获取当前访问次数
            "if curVisitNum == limitNum then\n" +  //如果当前访问次数等于限制次数
            "return 0\n"+  //返回0
            "else\n"+  //否则
            "redis.call('incrby',obj,'1'\n)" +  //将当前访问次数加1
            "redis.call('expire',obj,ARGV[2])\n" +  //设置过期时间
            "return curVisitNum + 1\n" +  //返回当前访问次数加1
            "end";

    public static boolean canVisit(Jedis jedis,String model,int limitNum,int limitTime){
        String r = jedis.eval(script,1,model,limitNum+"",limitTime+"").toString();  //执行Lua脚本
        return  !"0".equals(r);  //如果返回值不为0，则返回true，否则返回false
    }
}
```

```java
public class RequestDemo extends Thread{
    @Override
    public void run() {
        Jedis jedis = new Jedis("192.168.71.236",6379);  //创建连接Redis的客户端
        jedis.auth("123456");  //使用密码进行身份验证
        for (int i = 0;i<5;i++){
            String name = Thread.currentThread().getName();  //获取当前线程的名称
            boolean r = LimitByLuaUtil.canVisit(jedis,name,3,10);  //调用LimitByLuaUtil.canVisit方法判断当前是否可以访问
            if (r){
                System.out.println(name+"可以访问");  //如果可以访问，则输出线程名称和提示信息
            }else {
                System.out.println(name+"限制访问");  //如果不能访问，则输出线程名称和提示信息
            }
        }
    }

    public static void main(String[] args) {
        for (int i = 0;i<2;i++){
            new RequestDemo().start();  //创建并启动两个线程
        }
    }
}
```

## Redis与Springboot整合操作

RedisTemplate是Spring Boot提供的一个Redis客户端，用于操作Redis数据库。它封装了Redis的常用操作，如设置键值对、获取键值对、删除键值对、设置过期时间等。本文将介绍RedisTemplate的常用API，以及如何在Spring Boot中使用RedisTemplate。

#### 引入RedisTemplate

```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
<dependency>
	<groupId>org.apache.commons</groupId>
	<artifactId>commons-pool2</artifactId>
</dependency>
```

#### 连接Redis

```properties
spring.data.redis.database=0
spring.data.redis.host=192.168.71.236
spring.data.redis.port=6379
spring.data.redis.password=123456
```

#### 基本使用

```java
@Autowired
private RedisTemplate redisTemplate;

@GetMapping("/hello")
public String hello(){
        redisTemplate.opsForValue().set("hello","zhangsan");
        String name = (String) redisTemplate.opsForValue().get("hello");
        redisTemplate.expire("hello",20, TimeUnit.SECONDS);

        return "欢迎访问"+name;
}
```

#### RedisTemplate的常用API

##### 设置键值对

RedisTemplate提供了opsForValue()方法来操作字符串类型的键值对，例如：

```java
redisTemplate.opsForValue().set("name", "zhangsan");
```

这个方法会将字符串"zhangsan"存储到键"name"中。如果键"name"已存在，则会覆盖原来的值。

##### 获取键值对

可以使用opsForValue()方法的get()方法获取键值对的值，例如：

```java
String name = redisTemplate.opsForValue().get("name");
```

这个方法会返回键"name"对应的值"zhangsan"。

##### 删除键值对

可以使用opsForValue()方法的delete()方法删除键值对，例如：

```java
redisTemplate.opsForValue().delete("name");
```

这个方法会删除键"name"对应的键值对。

##### 设置过期时间

可以使用opsForValue()方法的expire()方法设置键值对的过期时间，例如：

```java
redisTemplate.opsForValue().set("name", "zhangsan");
redisTemplate.expire("name", 10, TimeUnit.SECONDS);
```

这个方法会将键"name"的过期时间设置为10秒钟。在10秒钟后，键"name"将自动过期并被删除。

##### 操作Hash类型的键值对

可以使用opsForHash()方法来操作Hash类型的键值对，例如：

```java
redisTemplate.opsForHash().put("user", "name", "zhangsan");
redisTemplate.opsForHash().put("user", "age", 18);
```

这个方法会将Hash键"user"中的"name"和"age"设置为"zhangsan"和18。

##### 获取Hash类型的键值对

可以使用opsForHash()方法的get()方法获取Hash类型键值对的值，例如：

```java
String name = (String)redisTemplate.opsForHash().get("user", "name");
int age = (int)redisTemplate.opsForHash().get("user", "age");
```

这个方法会返回Hash键"user"中"name"对应的值"zhangsan"和"age"对应的值18。

##### 删除Hash类型的键值对

可以使用opsForHash()方法的delete()方法删除Hash类型的键值对，例如：

```java
redisTemplate.opsForHash().delete("user", "name");
```

这个方法会删除Hash键"user"中的"name"键值对。

##### 设置Hash类型键值对的过期时间

可以使用opsForHash()方法的expire()方法设置Hash类型键值对的过期时间，例如：

```java
redisTemplate.opsForHash().put("user", "name", "zhangsan");
redisTemplate.expire("user", 10, TimeUnit.SECONDS);
```

这个方法会将Hash键"user"的过期时间设置为10秒钟。在10秒钟后，Hash键"user"将自动过期并被删除。

##### 操作List类型的键值对

可以使用opsForList()方法来操作List类型的键值对，例如：

```java
redisTemplate.opsForList().leftPush("list", "zhangsan");
redisTemplate.opsForList().leftPush("list", "lisi");
```

这个方法会将"zhangsan"和"lisi"添加到List键"list"中。由于是从左侧添加，因此"lisi"会排在"zhangsan"的左边。

##### 获取List类型的键值对

可以使用opsForList()方法的range()方法获取List类型键值对的值，例如：

```java
List<String> list = redisTemplate.opsForList().range("list", 0, -1);
```

这个方法会返回List键"list"中的所有元素，即["lisi", "zhangsan"]。

##### 删除List类型的键值对

可以使用opsForList()方法的remove()方法删除List类型的键值对，例如：

```java
redisTemplate.opsForList().remove("list", 0, "zhangsan");
```

这个方法会删除List键"list"中所有值为"zhangsan"的元素。

##### 设置List类型键值对的过期时间

由于Redis本身并不支持对List类型键值对进行过期时间的设置，因此无法直接使用RedisTemplate的expire()方法来设置List类型键值对的过期时间。不过，我们可以通过在List中添加一个元素，然后设置这个元素的过期时间来达到类似的效果。例如：

```java
redisTemplate.opsForList().leftPush("list", "zhangsan");
redisTemplate.opsForValue().set("list:expire", "1");
redisTemplate.expire("list:expire", 10, TimeUnit.SECONDS);
```

这个方法会将"zhangsan"添加到List键"list"中，并在Redis中设置一个名为"list:expire"的键，值为"1"。然后，设置"list:expire"的过期时间为10秒钟。在10秒钟后，"list:expire"键将自动过期并被删除，这时候可以通过判断"list:expire"键是否存在来判断List键"list"是否过期。

##### 操作Set类型的键值对

可以使用opsForSet()方法来操作Set类型的键值对，例如：

```java
redisTemplate.opsForSet().add("set", "a", "b", "c");
```

这个方法会将"a"、"b"和"c"添加到Set键"set"中。

##### 获取Set类型的键值对

可以使用opsForSet()方法的members()方法获取Set类型键值对的值，例如：

```java
Set<String> set = redisTemplate.opsForSet().members("set");
```

这个方法会返回Set键"set"中的所有元素，即["a", "b", "c"]。

##### 删除Set类型的键值对

可以使用opsForSet()方法的remove()方法删除Set类型的键值对，例如：

```java
redisTemplate.opsForSet().remove("set", "a");
```

这个方法会删除Set键"set"中的值为"a"的元素。

##### 设置Set类型键值对的过期时间

与List类型键值对类似，Redis本身并不支持对Set类型键值对进行过期时间的设置。可以通过在Set中添加一个元素，然后设置这个元素的过期时间来达到类似的效果。例如：

```java
redisTemplate.opsForSet().add("set", "a", "b", "c");
redisTemplate.opsForValue().set("set:expire", "1");
redisTemplate.expire("set:expire", 10, TimeUnit.SECONDS);
```

这个方法会将"a"、"b"和"c"添加到Set键"set"中，并在Redis中设置一个名为"set:expire"的键，值为"1"。然后，设置"set:expire"的过期时间为10秒钟。在10秒钟后，"set:expire"键将自动过期并被删除，这时候可以通过判断"set:expire"键是否存在来判断Set键"set"是否过期。

#### 集成Spring Session

Spring Session是一个用于管理Web应用程序中用户会话的框架，它提供了一种基于Spring的方式来处理用户会话，可以将用户会话存储在多种后端存储中，如Redis、MongoDB等，同时也提供了一种统一的API来访问这些存储。

##### 引入Spring Session

```xml
<dependency>
    <groupId>org.springframework.session</groupId>
    <artifactId>spring-session-core</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.session</groupId>
    <artifactId>spring-session-data-redis</artifactId>
</dependency>
```

##### 基本使用

```java
@GetMapping("/login")
    public String login(String username, String password, HttpSession session){
        session.setAttribute("username",username);
        return "登录成功";
}
```

session会自动存入redis中。
