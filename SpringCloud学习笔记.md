# SpringCloud学习笔记

Spring Cloud是一个基于Spring Framework的开源框架，提供了一系列的工具和框架，用于开发分布式系统中的常见模式，例如服务发现、配置管理、负载均衡、断路器等。

使用Spring Cloud的作用如下：

1. 微服务架构的支持：Spring Cloud提供了一系列的组件来构建和部署微服务应用程序。
2. 分布式系统的管理：Spring Cloud提供了一些有用的工具，如服务发现、负载均衡、断路器等，有助于管理分布式系统中的复杂性。
3. 云原生应用的支持：Spring Cloud是云原生应用的理想选择，可以在云上部署和管理应用程序，支持多种云和容器化平台。
4. 开放性和灵活性：Spring Cloud中的组件和工具都是开源的，可以轻松地与其他框架和技术集成，具有很高的灵活性。

## Eureka 服务注册与发现

Eureka是Netflix开源的基于REST的服务治理（Service Discovery）组件，主要用于服务注册和发现。Eureka的设计目标是实现服务注册与发现的自动化管理，以支持微服务架构模式下的应用程序开发和部署。

Eureka包含两个组件：Eureka Server和Eureka Client。Eureka Server是服务注册中心，它负责接收服务实例的注册请求，并将服务实例的元数据信息存储在内存中。Eureka Client则是服务提供者和服务消费者的客户端，它向Eureka Server注册服务实例，并定期向Eureka Server发送心跳请求以保持服务实例的可用性。

使用Eureka可以方便地进行服务的注册和发现，避免了服务之间硬编码的情况，同时也提供了对服务实例的健康检查和自动剔除的支持，提高了系统的可靠性和可用性。

**添加依赖**

父依赖：

```xml
<dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
        </dependency>
        <dependency>
            <groupId>com.mysql</groupId>
            <artifactId>mysql-connector-j</artifactId>
        </dependency>
    </dependencies>

    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.mybatis.spring.boot</groupId>
                <artifactId>mybatis-spring-boot-starter</artifactId>
                <version>3.0.0</version>
            </dependency>
            <dependency>
                <groupId>org.springframework.cloud</groupId>
                <artifactId>spring-cloud-dependencies</artifactId>
                <version>Dalston.SR3</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
            <dependency>
                <groupId>org.springframework.cloud</groupId>
                <artifactId>spring-cloud-dependencies</artifactId>
                <version>2022.0.1</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
```

### Eureka-Server模块-配置Eureka

**添加依赖**

```xml
<dependencies>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-netflix-eureka-server</artifactId>
            <version>4.0.0</version>
        </dependency>
    </dependencies>
```

**启动类**

```java
@SpringBootApplication
@EnableEurekaServer
public class EurekaApplication {
    public static void main(String[] args) {
        SpringApplication.run(EurekaApplication.class,args);
    }
}
```

**配置文件**

```yml
erver:
  port: 8888
eureka:
  client:
    register-with-eureka: false
    fetch-registry: false
    service-url:
      defaultZone: http://localhost:8888/eureka
```



### Commons模块-通用实体类

```java
@Data
public class User {
    Integer uid;
    String name;
    String sex;
}
```

```java
@Data
public class Book {
    Integer bid;
    String title;
    String desc;
}
```

```java
@Data
public class Borrow {
    Integer id;
    Integer uid;
    Integer bid;
}
```

### User-Service模块-用户服务

**添加依赖**

```xml
<dependencies>
        <dependency>
            <groupId>org.mybatis.spring.boot</groupId>
            <artifactId>mybatis-spring-boot-starter</artifactId>
        </dependency>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>commons</artifactId>
            <version>0.0.1-SNAPSHOT</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
            <version>4.0.0</version>
        </dependency>
    </dependencies>
```

**Mapper**

```java
@Mapper
public interface UserMapper {
    @Select("select * from DB_USER where uid = #{uid}")
    User getUserById(Integer uid);
}
```

**Service**

```java
public interface UserService {
    User getUserById(Integer uid);
}
```

**ServiceImpl**

```java
@Service
public class UserServiceImpl implements UserService {
    @Resource
    UserMapper mapper;
    @Override
    public User getUserById(Integer uid) {
        return mapper.getUserById(uid);
    }
}
```

**Controller**

```java
@RestController
public class UserController {
    @Resource
    UserService service;
    @RequestMapping("/user/{uid}")
    public User findUserById(@PathVariable("uid")Integer uid){
        System.out.println("我被调用了！");
        return service.getUserById(uid);
    }
}
```

**启动类**

```java
@SpringBootApplication
public class UserApplication {
    public static void main(String[] args) {
        SpringApplication.run(UserApplication.class,args);
    }
}
```

**配置文件**

```yml
spring:
  application:
    name: userservice
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/cloudstudy
    username: root
    password: 123456
eureka:
  client:
    service-url:
      defaultZone: http://localhost:8888/eureka
```

### Book-Service模块-书籍服务

**添加依赖**

```
<dependencies>
        <dependency>
            <groupId>org.mybatis.spring.boot</groupId>
            <artifactId>mybatis-spring-boot-starter</artifactId>
        </dependency>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>commons</artifactId>
            <version>0.0.1-SNAPSHOT</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
            <version>4.0.0</version>
        </dependency>
    </dependencies>
```

**Mapper**

```java
@Mapper
public interface BookMapper {
    @Select("select * from DB_BOOK where bid = #{bid}")
    Book getBookById(Integer bid);
}
```

**Service**

```java
public interface BookService {
    Book getBookById(Integer bid);
}
```

**ServiceImpl**

```java
@Service
public class BookServiceImpl implements BookService {
    @Resource
    BookMapper bookMapper;

    @Override
    public Book getBookById(Integer bid) {
        return bookMapper.getBookById(bid);
    }
}
```

**Contorller**

```java
@RestController
public class BookController {

    @Resource
    BookService service;

    @RequestMapping("/book/{bid}")
    Book findBookById(@PathVariable("bid")Integer bid){
        return service.getBookById(bid);
    }
}
```

**启动类**

```java
@SpringBootApplication
public class BookApplication {
    public static void main(String[] args) {
        SpringApplication.run(BookApplication.class,args);
    }
}
```

**配置文件**

```yml
server:
  port: 8101
spring:
  application:
    name: bookservice
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/cloudstudy
    username: root
    password: 123456
eureka:
  client:
    service-url:
      defaultZone: http://localhost:8888/eureka
```

### Borrow-Service模块-借阅服务

**添加依赖**

```xml
<dependencies>
        <dependency>
            <groupId>org.mybatis.spring.boot</groupId>
            <artifactId>mybatis-spring-boot-starter</artifactId>
        </dependency>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>commons</artifactId>
            <version>0.0.1-SNAPSHOT</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
            <version>4.0.0</version>
        </dependency>
    </dependencies>
```

**Entity**

```java
@Data
@AllArgsConstructor
public class UserBorrowDetail {
    User user;
    List<Book>bookList;
}
```

**Mapper**

```java
@Mapper
public interface BorrowMapper {
    @Select("select * from DB_BORROW where uid = #{uid}")
    List<Borrow> getBorrowByUid(Integer uid);
    @Select("select * from DB_BORROW where bid = #{bid}")
    List<Borrow> getBorrowByBid(Integer uid);
    @Select("select * from DB_BORROW where bid = #{bid} and uid = #{uid}")
    Borrow getBorrow(Integer uid,Integer bid);
}
```

**Config**

```java
@Configuration
public class BeanConfiguration {
    @Bean
    @LoadBalanced
    public RestTemplate restTemplate(){
        return new RestTemplate();
    }
}
```

**Service**

```java
public interface BorrowService {
    UserBorrowDetail getUserBoorowDetailByUid(Integer uid);
}
```

**ServiceImpl**

```java
@Service
public class BorrowServiceImpl implements BorrowService {
    @Resource
    BorrowMapper mapper;
    @Resource
    RestTemplate template;
    @Override
    public UserBorrowDetail getUserBoorowDetailByUid(Integer uid) {
        List<Borrow> borrow = mapper.getBorrowByUid(uid);
        User user = template.getForObject("http://userservice/user/"+uid,User.class);
        List<Book> bookList = borrow
                .stream()
                .map(b->template.getForObject("http://bookservice/book/"+b.getBid(), Book.class))
                .collect(Collectors.toList());
        return new UserBorrowDetail(user,bookList);
    }
}
```

**Controller**

```java
@RestController
public class BorrowController {
    @Resource
    BorrowService service;

    @RequestMapping("/borrow/{uid}")
    UserBorrowDetail findUserBorrows(@PathVariable("uid") Integer uid){
        return service.getUserBoorowDetailByUid(uid);
    }
}
```

**启动类**

```java
@SpringBootApplication
public class BorrowApplication {
    public static void main(String[] args) {
        SpringApplication.run(BorrowApplication.class,args);
    }
}
```

**配置文件**

```yml
server:
  port: 8201
spring:
  application:
    name: borrowservice
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/cloudstudy
    username: root
    password: 123456
eureka:
  client:
    service-url:
      defaultZone: http://localhost:8888/eureka
```

### 实现简单的负载均衡

在这里，划分两个用户服务，即建立用户服务集群。当01号用户服务崩溃时，这并不会导致整个用户服务崩溃，请求会被放到02号用户处理：

[![20230403-182350.png](https://i.postimg.cc/9FpW5bv9/20230403-182350.png)](https://postimg.cc/TpK8nV22)

应该首先启动Eureka服务：

[![image.png](https://i.postimg.cc/3Nzkv9jM/image.png)](https://postimg.cc/vxL8RrSX)

待启动完毕其它服务时，可在8888端口查阅注册服务：

[![image.png](https://i.postimg.cc/hGNHz5hb/image.png)](https://postimg.cc/qtXmWQsz)

### 注册中心高可用配置

虽然Eureka能够实现服务注册和发现，但如果Eureka服务器崩溃了，那么所有需要用到服务发现的微服务就失效了。为了避免该问题，我们可以搭建Eureka集群。

## LoaderBalancer 负载均衡

负载均衡是一种将网络流量分配到多个服务器上的技术，以提高系统的性能、可靠性和可扩展性。在高负载情况下，负载均衡器可以避免单个服务器过载，从而提高整个系统的可用性。负载均衡器还可以确保所有服务器的工作负载均匀分配，从而提高系统的效率。

**在Spring Cloud 2020.0.x版本中，Ribbon已经被弃用，不再是Spring Cloud的默认负载均衡器。**在新的Spring Cloud版本中，Spring Cloud LoadBalancer取代了Ribbon，成为Spring Cloud的默认负载均衡器。Spring Cloud LoadBalancer是一个基于reactive的负载均衡器，它提供了一些新的特性和更好的性能表现，同时也更加灵活和易于扩展。

在Spring Cloud中，LoadBalancer注解是用于标记一个方法，该方法将使用负载均衡算法（默认为轮询）从多个服务实例中选择一个来处理请求。LoadBalancer注解可以与RestTemplate、Feign、WebClient等Spring Cloud组件一起使用。

LoadBalancer注解的作用是将负载均衡的逻辑集成到应用程序中，让应用程序能够自动选择最佳的服务实例来处理请求。这可以提高应用程序的可用性和可扩展性，因为它可以确保所有服务实例都得到充分利用，并避免单个实例过载。

### 自定义随机负载均衡

```java
public class LoadBalancerConfig {
    @Bean
    public ReactorLoadBalancer<ServiceInstance> randomLoadBalancer(Environment environment, LoadBalancerClientFactory loadBalancerClientFactory){
        String name = environment.getProperty(loadBalancerClientFactory.PROPERTY_NAME);
        return new RandomLoadBalancer(loadBalancerClientFactory.getLazyProvider(name, ServiceInstanceListSupplier.class),name);
    }
}
```

这段代码定义了一个名为 LoadBalancerConfig 的 Java 类，该类用于配置负载均衡器。其中包含了一个名为 randomLoadBalancer 的公共方法，该方法用于创建一个基于随机策略的负载均衡器实例，用于在多个服务实例之间均衡请求。

下面是对每行代码的详细解释：

1. `@Bean`

这是一个注解，用于将该方法返回的对象注册到 Spring 容器中，以便其他组件可以使用该对象。在这段代码中，该注解将随机负载均衡器实例注册到 Spring 容器中。

2. `public ReactorLoadBalancer<ServiceInstance> randomLoadBalancer(Environment environment, LoadBalancerClientFactory loadBalancerClientFactory)`

这是一个公共方法，它接受两个参数：environment 和 loadBalancerClientFactory。environment 是 Spring 环境对象，用于检索属性。loadBalancerClientFactory 是负载均衡器客户端工厂对象，用于创建负载均衡器。

3. `String name = environment.getProperty(loadBalancerClientFactory.PROPERTY_NAME)`

这行代码从 environment 对象中获取名为 loadBalancerClientFactory.PROPERTY_NAME 的属性值，并将其赋值给变量 name。这个属性用于指定要使用的服务名称。

4. `loadBalancerClientFactory.getLazyProvider(name, ServiceInstanceListSupplier.class)`

这行代码创建一个 Lazy Provider 对象，该对象提供了 ServiceInstanceListSupplier 的延迟加载。Lazy Provider 对象是一种懒加载机制，只有在需要时才会创建对象实例。

5. `new RandomLoadBalancer(lazyProvider, name)`

这行代码创建一个新的基于随机策略的负载均衡器实例。它接受两个参数：lazyProvider 和 name。lazyProvider 是上面创建的 Lazy Provider 对象，它提供了 ServiceInstanceListSupplier 的延迟加载。name 是服务名称，用于标识要负载均衡的服务实例。

6. `return new RandomLoadBalancer(loadBalancerClientFactory.getLazyProvider(name, ServiceInstanceListSupplier.class),name)`

最后，该方法返回新创建的随机负载均衡器实例。它使用 loadBalancerClientFactory.getLazyProvider 方法创建 Lazy Provider 对象，然后将该对象和服务名称传递给 RandomLoadBalancer 构造函数来创建负载均衡器实例。

总的来说，这段代码的作用是创建一个基于随机策略的负载均衡器实例，用于在多个服务实例之间均衡请求。它使用 Spring 容器中注册的负载均衡器客户端工厂对象，以及指定的服务名称来创建负载均衡器实例。同时，它还使用 Lazy Provider 对象来实现延迟加载，以提高性能。

```java
@Configuration
@LoadBalancerClient(value = "userservice",      //指定为 userservice服务，只要是调用此服务都会使用我们指定的策略
                    configuration = LoadBalancerConfig.class)  //指定我们刚刚定义好的配置类
public class BeanConfiguration {
    @Bean
    @LoadBalanced
    public RestTemplate restTemplate(){
        return new RestTemplate();
    }
}
```

这段代码定义了一个名为 BeanConfiguration 的 Java 类，用于配置 RestTemplate 和负载均衡器。以下是对该代码的详细解释：

1. `@Configuration`

这是一个注解，用于标识该类为一个 Spring 配置类。在这个类里面，我们可以定义和配置 bean。

2. `@LoadBalancerClient(value = "userservice", configuration = LoadBalancerConfig.class)`

这是一个注解，用于指定要使用的负载均衡器和配置类。其中，value 属性指定要负载均衡的服务名称，configuration 属性指定要使用的负载均衡器配置类。这里指定的是名为 "userservice" 的服务，并使用了 LoadBalancerConfig 类作为负载均衡器的配置类。

3. `public class BeanConfiguration {`

这是一个公共类，名为 BeanConfiguration。

4. `@Bean`

这是一个注解，用于将该方法返回的对象注册为 Spring 容器中的 bean。在这个类里面，我们定义了一个名为 restTemplate 的 bean。

5. `@LoadBalanced`

这是一个注解，用于指示 RestTemplate 使用负载均衡器来分配请求。在这个类里面，我们将 restTemplate 标记为 @LoadBalanced，这样 RestTemplate 就能够使用负载均衡器来选择目标服务实例。

6. `public RestTemplate restTemplate() { return new RestTemplate(); }`

这是一个公共方法，名为 restTemplate，返回一个 RestTemplate 对象。我们使用了 new RestTemplate() 来创建 RestTemplate 实例，并将其作为 bean 注册到 Spring 容器中。

综上所述，这段代码的作用是配置了一个 RestTemplate 实例并使用了负载均衡器来选择目标服务实例。我们使用了 @Configuration 注解标识 BeanConfiguration 类为 Spring 配置类，使用了 @LoadBalancerClient 注解指定要使用的负载均衡器和配置类，使用了 @Bean 注解将 restTemplate 对象注册为 Spring 容器中的 bean，并使用了 @LoadBalanced 注解指示 RestTemplate 使用负载均衡器来分配请求。

### 使用OpenFeign实现负载均衡

OpenFeign是一个基于Netflix Feign的Java HTTP客户端开发工具，它是Spring Cloud生态系统中的一部分，用于简化HTTP客户端的开发。

与传统的HTTP客户端相比，OpenFeign提供了更加简洁的声明式API定义方式，使得开发者可以更加便捷地定义和调用HTTP接口。使用OpenFeign，可以通过接口定义来描述服务之间的交互，而无需手动编写HTTP请求和响应处理的代码。

OpenFeign还提供了一些常用的功能，例如请求重试、请求超时、Hystrix支持等，这些功能都可以通过简单的配置来启用。

另外，OpenFeign还提供了插件机制，可以让开发者通过自定义插件来扩展其功能。例如，可以通过自定义插件来实现请求重试、请求拦截器等功能。

**@FeignClient是一个Spring Cloud提供的注解，用于声明一个基于OpenFeign的服务调用客户端。**

通过在客户端接口上添加@FeignClient注解，你可以将该接口定义为一个Feign客户端，用于调用其他微服务提供的REST API。

@FeignClient注解有以下几个参数：

1. name：指定调用的微服务名称，该名称将作为服务发现的key来获取对应的微服务实例列表。
2. url：指定调用的URL，如果指定了该参数，则将忽略name参数。
3. fallback：指定服务降级处理的类，当调用失败时，将会使用该类中的方法来处理降级逻辑。
4. configuration：指定Feign的配置类，用于配置Feign客户端的行为。
5. path：指定调用的URL路径，用于在调用时拼接到URL之后。

使用@FeignClient注解定义的接口，可以像调用本地方法一样调用远程服务接口，极大地简化了服务调用的开发难度。

需要注意的是，@FeignClient注解是基于OpenFeign实现的，如果你想使用其他的HTTP客户端工具，可以考虑使用@RestClient注解来定义你的REST客户端接口。

我们可以使用@FeignClient注解实现负载均衡：

**client类**

```java
@FeignClient("userservice")  //声明为userservice服务的HTTP请求客户端
public interface UserClient {
    @RequestMapping("/user/{uid}")
    User findUserById(@PathVariable("uid")Integer uid);
}
```

```java
@FeignClient("bookservice")
public interface BookClient {
    @RequestMapping("/book/{bid}")
    Book findBookById(@PathVariable("bid")Integer bid);
}
```

**ServiceImpl类**

```java
@Service
public class BorrowServiceImpl implements BorrowService {
    @Resource
    BorrowMapper mapper;
    @Resource
    UserClient userClient;
    @Resource
    BookClient bookClient;
    @Override
    public UserBorrowDetail getUserBoorowDetailByUid(Integer uid) {
        List<Borrow> borrow = mapper.getBorrowByUid(uid);
        User user = userClient.findUserById(uid);
        List<Book> bookList = borrow
                .stream()
                .map(b->bookClient.findBookById(b.getBid()))
                .collect(Collectors.toList());
        return new UserBorrowDetail(user,bookList);
    }
}
```

这段代码定义了一个 BorrowServiceImpl 类，该类实现了 BorrowService 接口。以下是对该代码的详细解释：

1. `@Service`

这是一个注解，用于标识该类为一个 Spring 服务类。在这个类里面，我们可以定义服务的具体实现。

2. `public class BorrowServiceImpl implements BorrowService {`

这是一个公共类，名为 BorrowServiceImpl，并实现了 BorrowService 接口。

3. `@Resource`

这是一个注解，用于将指定的 bean 注入到当前类中。在这个类里面，我们注入了 BorrowMapper、UserClient 和 BookClient 三个 bean。

4. `BorrowMapper mapper;`

这是一个私有变量，名为 mapper，它是一个 BorrowMapper 类型的对象。BorrowMapper 是一个用于操作数据库中 Borrow 表的 mapper。

5. `UserClient userClient;`

这是一个私有变量，名为 userClient，它是一个 UserClient 类型的对象。UserClient 是一个用于调用远程用户服务的客户端。

6. `BookClient bookClient;`

这是一个私有变量，名为 bookClient，它是一个 BookClient 类型的对象。BookClient 是一个用于调用远程图书服务的客户端。

7. `public UserBorrowDetail getUserBoorowDetailByUid(Integer uid) {`

这是一个公共方法，名为 getUserBoorowDetailByUid，它接受一个 Integer 类型的 uid 参数，并返回一个 UserBorrowDetail 类型的对象。该方法用于获取指定用户的借阅详情。

8. `List<Borrow> borrow = mapper.getBorrowByUid(uid);`

这是一个变量声明语句，用于获取指定用户的借阅记录。通过调用 mapper 的 getBorrowByUid 方法，我们可以从数据库中获取指定用户的借阅记录。

9. `User user = userClient.findUserById(uid);`

这是一个变量声明语句，用于获取指定用户的信息。通过调用 userClient 的 findUserById 方法，我们可以调用远程用户服务，从而获取指定用户的信息。

10. `List<Book> bookList = borrow.stream().map(b->bookClient.findBookById(b.getBid())).collect(Collectors.toList());`

这是一个变量声明语句，用于获取指定用户借阅的所有图书信息。通过调用 bookClient 的 findBookById 方法，我们可以调用远程图书服务，从而获取指定图书的信息。这里使用了 Java 8 中的 Stream API，将 borrow 中的每一个借阅记录映射为相应的图书信息，并将结果收集到一个列表中。

11. `return new UserBorrowDetail(user,bookList);`

这是一个返回语句，用于返回一个 UserBorrowDetail 类型的对象，它包含了指定用户的信息和借阅详情中的所有图书信息。

综上所述，这段代码的作用是实现了一个名为 getUserBoorowDetailByUid 的方法，用于获取指定用户的借阅详情。在这个方法里面，我们使用了 BorrowMapper、UserClient 和 BookClient 三个 bean，分别用于从数据库、远程用户服务和远程图书服务获取相关信息，并将结果封装到一个 UserBorrowDetail 对象中返回。

**启动类**

```java
@SpringBootApplication
@EnableFeignClients
public class BorrowApplication {
    public static void main(String[] args) {
        SpringApplication.run(BorrowApplication.class,args);
    }
}
```

## GateWay 路由网关

当谈到在Spring Cloud中使用网关（Gateway）时，首先需要理解什么是网关以及为什么需要网关。

**网关是一个应用程序，它充当进入系统的所有请求的前置接收器。**它可以通过执行一些基本功能来帮助开发人员构建微服务体系结构。这些功能包括路由请求、负载均衡、安全认证和熔断等。

在一个微服务架构中，通常有多个服务，每个服务都可以单独部署、扩展和升级。这些服务之间相互协作来提供完整的业务功能。然而，这种微服务架构也带来了一些挑战，例如如何管理服务之间的依赖关系、如何做服务发现、如何进行负载均衡、如何实现统一的安全认证等等。这就是网关发挥作用的地方。

Spring Cloud Gateway是Spring Cloud生态系统中的一个网关组件，它提供了一个基于路由的API，可以将请求路由到不同的微服务上。Spring Cloud Gateway可以与Eureka、Consul、Zookeeper等服务发现组件集成，实现自动化的服务发现和负载均衡。同时，Spring Cloud Gateway还支持多种安全认证机制，例如OAuth2、JWT等。

以下是在具体业务场景中使用Spring Cloud Gateway的一些例子：

1. 服务路由

假设我们有两个微服务：订单服务和用户服务。每个服务都有自己的API。我们可以使用Spring Cloud Gateway来将请求路由到不同的服务上。例如，对于以`/orders`为前缀的请求，我们可以将其路由到订单服务上；对于以`/users`为前缀的请求，我们可以将其路由到用户服务上。

2. 负载均衡

如果我们有多个实例运行同一个服务，我们可以使用Spring Cloud Gateway来实现负载均衡。

3. 安全认证

Spring Cloud Gateway可以与Spring Security和OAuth2等安全框架集成，实现统一的安全认证机制。例如，我们可以在网关上实现OAuth2认证，然后将请求路由到需要认证的微服务上。

4. 熔断

当服务出现故障或不可用时，我们可以使用熔断机制来防止应用程序崩溃。Spring Cloud Gateway内置了熔断机制，可以在服务不可用时返回一个默认的响应，避免客户端收到错误的响应。

**如何理解GateWay中的路由与Vue.js中路由的差异？**

Spring Cloud Gateway是一个后端网关，它用于管理微服务之间的请求流量。它可以根据请求的URL、请求头、请求参数等信息，将请求路由到不同的微服务实例上。Spring Cloud Gateway还可以实现负载均衡、安全认证和熔断等功能，以确保微服务的高可用性和稳定性。

Vue.js的路由是一个前端路由，它用于管理单页应用程序中的URL。Vue.js的路由可以通过URL参数、路由参数、查询参数等信息，控制显示哪个组件，以实现单页应用程序的页面切换和数据加载等功能。

虽然二者都用于管理请求，但它们的目的和用法是不同的。Spring Cloud Gateway是用于管理微服务之间的请求流量，而Vue.js的路由是用于管理单页应用程序中的URL。

此外，Spring Cloud Gateway是在后端服务器上运行的，而Vue.js的路由是在前端浏览器中运行的。Spring Cloud Gateway的实现方式通常是基于反向代理和路由规则，而Vue.js的路由则是基于浏览器的History API和路由配置。因此，它们的实现方式也有很大的不同。

### 部署网关

在项目中构建一个gateway-server模块，用以部署网关，配置路由，其中应包含以下内容：

**添加依赖**

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-starter-gateway</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
    </dependency>
</dependencies>
```

**配置文件**

```yml
server:
  port: 8500
eureka:
  client:
    service-url:
      defaultZone: http://localhost:8801/eureka,http://localhost:8802/eureka
spring:
  application:
    name: gateway
  main:
    web-application-type: reactive
  cloud:
    gateway:
      # 配置路由，此处为列表，每一项包含诸多信息
      routes:
        - id: borrow-service  #路由名称
          uri: lb://borrowservice #路由的地址，lb表示使用负载均衡的微服务，也可以使用http正常转发
          predicates: #路由规则，断言什么请求会被路由
            - Path=/borrow/** #只要是访问这个路径，一律都被路由至上方指定的服务
```

**启动类**

```java
@SpringBootApplication
public class GateWayApplication {
    public static void main(String[] args) {
        SpringApplication.run(GateWayApplication.class,args);
    }
}
```

### 自定义全局路由过滤器

**配置文件**

```yml
server:
  port: 8500
eureka:
  client:
    service-url:
      defaultZone: http://localhost:8801/eureka,http://localhost:8802/eureka
spring:
  application:
    name: gateway
  main:
    web-application-type: reactive
  cloud:
    gateway:
      # 配置路由，此处为列表，每一项包含诸多信息
      routes:
        - id: borrow-service  #路由名称
          uri: lb://borrowservice #路由的地址，lb表示使用负载均衡的微服务，也可以使用http正常转发
          predicates: #路由规则，断言什么请求会被路由
            - Path=/borrow/** #只要是访问这个路径，一律都被路由至上方指定的服务
        - id: book-service
          uri: lb://bookservice
          predicates:
            - Path=/book/**
          filters:
            - AddRequestHeader=Test,HelloWorld!
            # AddRequestHeader 添加请求头信息
```

**自定义过滤器**

```java
@Component //标记为Spring容器中的一个组件
public class TestFilter implements GlobalFilter { //实现GlobalFilter接口的过滤器类
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) { //实现filter方法
        ServerHttpRequest request = exchange.getRequest(); //获取请求对象
        System.out.println(request.getQueryParams()); //打印请求参数
        List<String> value = request.getQueryParams().get("test"); //获取名为test的查询参数
        if (value != null && value.contains("1")){ //如果查询参数中包含值为1的test参数
            return chain.filter(exchange); //继续执行过滤器链
        }else {
            return exchange.getResponse().setComplete(); //返回响应并完成请求处理
        }
    }
}
```

**改写book-controller**

```java
@RestController
public class BookController {

    @Resource
    BookService service;

    @RequestMapping("/book/{bid}")
    Book findBookById(@PathVariable("bid")Integer bid,
                      HttpServletRequest request){
        System.out.println(request.getHeader("Test"));
        return service.getBookById(bid);
    }
}
```

### 使用Ordered设置过滤器之间的顺序

当Spring Cloud Gateway中有多个Gateway Filter时，可以使用`ordered`属性来指定它们的执行顺序。

Gateway Filter的执行顺序通过`Ordered`接口来确定，实现该接口并提供一个返回值表示顺序的方法`getOrder()`。Spring Cloud Gateway中的Gateway Filter都实现了该接口，因此可以通过实现该接口并重写`getOrder()`方法来控制过滤器执行的顺序。

`ordered`属性用于指定过滤器的执行顺序，数值越小的过滤器优先执行。默认情况下，Gateway Filter的执行顺序是按照它们在过滤器链中的声明顺序执行的。

```java
@Component
public class TestFilter implements GlobalFilter, Ordered {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        System.out.println(request.getQueryParams());
        List<String> value = request.getQueryParams().get("test");
        if (value != null && value.contains("1")){
            return chain.filter(exchange);
        }else {
            return exchange.getResponse().setComplete();
        }
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
```



**截止以上内容，大多为基于Netflix或Spring官方推出，许多内容现已逐渐退出支持，因此，以下内容将基于目前持续维护的SpringCloud Alibaba进行深入学习。**



##  Nacos 更加全能的注册中心

官方文档：[Nacos Spring Cloud 快速开始](https://nacos.io/zh-cn/docs/quick-start-spring-cloud.html)

仓库地址：[alibaba/nacos: an easy-to-use dynamic service discovery, configuration and service management platform for building cloud native applications. (github.com)](https://github.com/alibaba/nacos)

在Nacos官方Github仓库下载Nacos后，解压其内容至开发目录，然后切换到nacos的bin目录下，在终端中使用该命令：

```shell
 .\startup.cmd -m standalone 
```

**更为便捷的方式是配置脚本服务：**

[![image.png](https://i.postimg.cc/QdxpRL0q/image.png)](https://postimg.cc/JGvDkFwy)

### 使用Nacos实现服务注册与发现

**添加依赖**

```xml
<dependency>
	<groupId>org.springframework.cloud</groupId>
	<artifactId>spring-cloud-dependencies</artifactId>
	<version>2022.0.1</version>
</dependency>
<dependency>
	<groupId>com.alibaba.cloud</groupId>
	<artifactId>spring-cloud-alibaba-dependencies</artifactId>
	<version>2022.0.0.0-RC1</version>
</dependency>
```

以book-service为例：

**引入discovery**

```xml
<dependency>
	<groupId>com.alibaba.cloud</groupId>
	<artifactId>spring-cloud-starter-alibaba-nacos-discovery</artifactId>
	<version>2022.0.0.0-RC1</version>
</dependency>
```

**配置文件**

```yml
server:
  port: 8201
spring:
  application:
    name: borrow-service
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/cloudstudy
    username: root
    password: 123456
  cloud:
    nacos:
      discovery:
        server-addr: localhost:8848
```

全部配置完成后，可在Nacos查看到：

[![image.png](https://i.postimg.cc/bJpyh2dK/image.png)](https://postimg.cc/Y4DKN063)

### 使用Openfeign实现负载均衡

该部分内容与LoaderBalancer 负载均衡--使用Openfeign实现负载均衡一致。

### 临时实例与非临时实例

下面展示了Nacos中book-service服务集群的状态

[![image.png](https://i.postimg.cc/SsVXRY1z/image.png)](https://postimg.cc/r00yYsk8)

- 临时实例：和Eureka一样，通过心跳机制向Nacos发送请求保持在线状态，一旦心跳停止，代表实例下线，不保留实例信息。
- 非临时实例：由Nacos主动联系，如果连接失败，不会删除实例信息，而是将健康状态设为false，相当于会对某个实例进行持续性的监控。

**使用非临时实例：**

比如在borrow-service的配置文件中添加`ephemeral: false`：

```yml
server:
  port: 8201
spring:
  application:
    name: borrow-service
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/cloudstudy
    username: root
    password: 123456
  cloud:
    nacos:
      discovery:
        server-addr: localhost:8848
        ephemeral: false
```

然后**重启Nacos脚本服务，并重启borrow-service服务**：

[![image.png](https://i.postimg.cc/XYQPbd5y/image.png)](https://postimg.cc/Hr8z0JBp)

### 集群分区

例如，在配置编辑中增加：

```
spring.cloud.nacos.discovery.cluster-name=Chengdu
```

即可将该服务划分至Chengdu集群。

然后，在borrow-service的配置文件中修改配置文件：

```yml
server:
  port: 8201
spring:
  application:
    name: borrow-service
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/cloudstudy
    username: root
    password: 123456
  cloud:
    nacos:
      discovery:
        server-addr: localhost:8848
        ephemeral: false
        cluster-name: Chengdu
    loadbalancer:
      nacos:
        enabled: true
```

重启Nacos脚本服务，并重启borrow-service服务，即可优先调用Chengdu集群的服务。

对于处于同一集群下的多个实例，我们可以通过设置权重来分配调用服务的优先级（在某些情况下，一些服务器的性能较高，应优先调用），我们可以在`discovery`下添加`weight`属性（默认为1），即可设置服务权重。

### 命名空间

通过在discovery属性下填写namespace属性，可划分不同的命名空间。

当在nacos中创建好命名空间后，我们会得到该命名空间ID，亦即namespace的值，如：

[![image.png](https://i.postimg.cc/x8FLN2pk/image.png)](https://postimg.cc/V0nJ2381)

其值为：3566fbe3-0bf2-4332-bcb7-cdcfadc4e56f

进而实现不同命名空间下，如同沙盒式的隔离。

当然，同一个命名空间下，仍然可能会有不同的业务场景，因而可以通过group属性进行分组。

### Nacos集群搭建

可参考：[Docker之nacos集群部署(详细教你搭建)_docker部署nacos_落日飞行的博客-CSDN博客](https://blog.csdn.net/m0_53151031/article/details/123118920)

​				[Nacos集群搭建部署(超详细)_nacos 集群 部署_LaTa_Xiao的博客-CSDN博客](https://blog.csdn.net/weixin_45715596/article/details/116164652)

通过Nginx代理部署的Nacos：

[![image.png](https://i.postimg.cc/hPFftsr4/image.png)](https://postimg.cc/Z0cTfr2X)



## Sentinel 流量防卫兵

仓库地址：[alibaba/Sentinel: A powerful flow control component enabling reliability, resilience and monitoring for microservices. (面向云原生微服务的高可用流控防护组件) (github.com)](https://github.com/alibaba/Sentinel)

下载jar包后导入项目并编辑配置：

[![image.png](https://i.postimg.cc/g22C3FcY/image.png)](https://postimg.cc/JGSYWFBg)

在需要使用Sentinel的服务添加依赖：

```xml
<dependency>
            <groupId>com.alibaba.cloud</groupId>
            <artifactId>spring-cloud-starter-alibaba-sentinel</artifactId>
            <version>2022.0.0.0-RC1</version>
</dependency>
```

然后，在该服务配置文件的cloud属性下添加sentinel属性，比如：

```yml
server:
  port: 8101
spring:
  application:
    name: book-service
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/cloudstudy
    username: root
    password: 123456
  cloud:
    nacos:
      discovery:
        server-addr: localhost:8848
    sentinel:
      transport:
        dashboard: localhost:8858
```

### 流量控制

可以在面板中制定合适的流控规则：

比如，快速失败：

[![image.png](https://i.postimg.cc/sfQ7DKk1/image.png)](https://postimg.cc/HjmV60sC)

在该流控规则下，若一秒内访问多次该资源，页面会输出：

```
Blocked by Sentinel (flow limiting)
```

**流控模式**：

- 直接：只针对当前接口
- 关联：当其它接口超过阈值时，会导致当前接口被限流
- 链路：更细粒度的限流，能精确到具体方法

**使用链路模式：**

@SentinelResource注解指定到需要流控的具体方法，及实现类中的方法

```java
@SentinelResource("details")
    @Override
    public UserBorrowDetail getUserBoorowDetailByUid(Integer uid) {
        List<Borrow> borrow = mapper.getBorrowByUid(uid);

        User user = userClient.findUserById(uid);
        List<Book> bookList = borrow
                .stream()
                .map(b->bookClient.findBookById(b.getBid()))
                .collect(Collectors.toList());
        return new UserBorrowDetail(user,bookList);
    }
```

配置文件

```yml
    sentinel:
      transport:
        dashboard: localhost:8858
      web-context-unify: false
```

在控制器写一个borrow2，然后只针对其进行限流：

[![image.png](https://i.postimg.cc/SKp5rD9K/image.png)](https://postimg.cc/WdXXpmXR)

### 限流和异常处理

**返回自定义请求失败页面**

```java
@RequestMapping("/blocked")
    JSONObject blocked(){
        JSONObject object = new JSONObject();
        object.put("code",403);
        object.put("success",false);
        object.put("message","您的请求频率过快，请稍后重试");
        return object;
    }
```

配置文件

```yml
    sentinel:
      transport:
        dashboard: localhost:8858
      web-context-unify: false
      block-page: /blocked
```

**返回一种替代方案**

```java
@SentinelResource(value = "details",blockHandler = "blocked")
    @Override
    public UserBorrowDetail getUserBoorowDetailByUid(Integer uid) {
        List<Borrow> borrow = mapper.getBorrowByUid(uid);

        User user = userClient.findUserById(uid);
        List<Book> bookList = borrow
                .stream()
                .map(b->bookClient.findBookById(b.getBid()))
                .collect(Collectors.toList());
        return new UserBorrowDetail(user,bookList);
    }

    //替代方案
    public UserBorrowDetail blocked(Integer uid, BlockException e){
        return new UserBorrowDetail(null, Collections.emptyList());
    }
```

### 热点参数限流

```java
@RequestMapping("/test")
    @SentinelResource("test")
    String findUserBorrows2(@RequestParam(value = "a",required = false)String a,
                            @RequestParam(value = "b",required = false)String b,
                            @RequestParam(value = "c",required = false)String c){
        return "请求成功：a = "+a+",b = "+b+",c = "+c;
    }
```

[![image.png](https://i.postimg.cc/mrvNNJjr/image.png)](https://postimg.cc/p9BFP0gN)

可对索引为0（在这里是”a“）的参数进行限流。当请求包含该参数时，阻止其访问。

也可针对特定参数值进行限流：

[![image.png](https://i.postimg.cc/4dGwRj9S/image.png)](https://postimg.cc/KK9tnqQP)

### 服务熔断和降级

**熔断**

[![image.png](https://i.postimg.cc/J4Dtgy0d/image.png)](https://postimg.cc/ykKV38FF)

1.慢调用比例：

如果出现许久都处理不完的调用，有可能时服务出现故障，导致卡顿。该选项按照最大响应时间进行判定，如果一次请求的处理时间超过了指定的最大响应时间，那么就判定为慢调用。在一个统计时长里，如果请求数目大于最小请求数目，并且被判定为慢调用的请求比例已经超过了阈值，将触发熔断，经过熔断时长后，将会进入到半开状态进行试探。

尝试修改一个接口，模拟慢调用：

```java
@RequestMapping("/borrow2/{uid}")
    String findUserBorrows2(@PathVariable("uid") Integer uid) throws InterruptedException {
        Thread.sleep(1000);
        return "熔断";
    }
```

添加熔断规则：

[![image.png](https://i.postimg.cc/mgmyTX7g/image.png)](https://postimg.cc/cv8nmcDp)

2.异常比例：

与慢调用比例类似，不过这里判断的是出现异常的次数。只需将上方代码修改为抛出异常即可简单实现。

3.异常数：

和异常比例的唯一区别是，只要达到指定的异常数量，就熔断。

**自定义降级**

```java
@RequestMapping("/borrow2/{uid}")
    @SentinelResource(value = "findUserBorrows2",blockHandler = "test2")
    UserBorrowDetail findUserBorrows2(@PathVariable("uid") Integer uid) throws InterruptedException {
        throw new RuntimeException();
    }
    UserBorrowDetail test2(Integer uid, BlockException e){
        System.out.println(e.getClass());
        return new UserBorrowDetail(new User(), Collections.emptyList());
    }
```

添加熔断规则：

[![image.png](https://i.postimg.cc/J7c988Y3/image.png)](https://postimg.cc/qgqmcPTg)

我们借此得以调用自定义的替代方案test2。

**使用Feign对每个接口调用单独进行服务降级**

在配置文件的根分支下添加：

```yml
feign:
  sentinel:
    enabled: true
```

```
@Component
public class UserClientFallback implements UserClient{
    @Override
    public User findUserById(Integer uid) {
            User user = new User();
            user.setName("我是替代方案");
            return user;
    }
}
```

```
@FeignClient(value = "user-service",fallback = UserClientFallback.class)  //声明为userservice服务的HTTP请求客户端
public interface UserClient {
    @RequestMapping("/user/{uid}")
    User findUserById(@PathVariable("uid")Integer uid);
}
```

