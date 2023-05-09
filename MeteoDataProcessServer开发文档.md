# MeteoDataProcessServer开发文档

## 项目架构

[![image.png](https://i.postimg.cc/G2LnBc2C/image.png)](https://postimg.cc/2qKKMNhc)

### 基本运行

客户端应首先登录，向授权服务获取**授权码**，再使用获得的授权码请求授权服务颁发生命周期为12h的**Jwt令牌**。然后，客户端可在请求头中携带Jwt令牌以访问资源服务。例如，查询所有在录的气象站。此时数据分析服务应进行数据检查，如果数据库和redis中都不存在数据，则调用数据获取程序获取在录气象站信息。

对于气象数据获取程序而言，它应该首先向数据存储服务器请求登录（即客户端登录所用账户）获取16字节令牌，然后使用该令牌获取在录气象站信息，并以rdb形式持久化至redis中，即完成数据获取工作。接着，数据分析服务需要恢复该文件至redis，然后返还结果给客户端，同时需要将该数据持久化至MySQL数据库中。

### 当前开发情况

**现在能够完成的流程是：**

客户端应首先登录，向授权服务获取**授权码**，再使用获得的授权码请求授权服务颁发生命周期为12h的**Jwt令牌**。然后，客户端可在请求头中携带Jwt令牌以访问资源服务。例如，查询所有在录的气象站。数据分析服务能从redis和MySQL中获取结果返还结果给客户端。

**未能完成数据获取程序开发的原因：**

数据存储服务器尚未完成。但目前已经写好了token的获取，以及整体框架代码。现在，只需完成协议3中剩余接口即可。

**关于Python脚本：**

已经写好了相关系数矩阵、测试用假数据集生成器、Redis-to-MySQL持久化转换器。等数据获取程序完成时，需合作进行调整。

**关于清洗接口、建模和预报的Python脚本：**

等待开发完成后合作进行整合。

**关于微服务部署、服务注册与发现、统一API网关：**
计划技术栈为SpringCloud Alibaba，待项目最终完成再作集成，然后进行生产部署



## 开发环境

本项目使用了SpringBoot3.0.5版本，因此应该使自己的电脑具有JDK17的环境，可在[此处](https://www.oracle.com/cn/java/technologies/downloads/#java17)获取。

同时，还需要配备Python解释器以使得能执行Python脚本。在[此处](https://www.python.org/downloads/release/python-3104/)获取3.10.4版本。

接着，您需要在cmd命令行中键入如下命令以安装工具：

```powershell
pip install pandas numpy sqlalchemy pymysql
```

下面是详细的开发文档。

## 基于Spring Security6 及OAuth2的授权服务

目前网络中流行着大量Spring Security5的教程，然而在SpringBoot3.x版本中我们只能使用Spring Security6。同时，最新版本的Security废除了大量以前版本的写法，国内目前并没有太多关于Security 6 的教程文章，或许有，但浅尝辄止。在开发过程中，尝试了从国外技术媒体与官方英文文档学习了用法，他们的代码大量使用了Lamda表达式，因此有必要学习它的[用法](https://www.bilibili.com/video/BV1KM4y1U77Q/?spm_id_from=333.337.search-card.all.click&vd_source=f79495f1caad326722ff37b4b636a04b)。

在整个父项目中应具有如下依赖：

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>com.mysql</groupId>
        <artifactId>mysql-connector-j</artifactId>
    </dependency>
</dependencies>

<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.baomidou</groupId>
            <artifactId>mybatis-plus-boot-starter</artifactId>
            <version>3.5.2.7-SNAPSHOT</version>
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
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>druid-spring-boot-starter</artifactId>
            <version>1.2.6</version>
        </dependency>
    </dependencies>
</dependencyManagement>
```

### 核心依赖

创建我们自己的授权服务OAuth2Custom-Service，并添加如下核心依赖：

```xml
<dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-oauth2-authorization-server</artifactId>
            <version>1.0.2</version>
        </dependency>
        <dependency>
            <groupId>com.baomidou</groupId>
            <artifactId>mybatis-plus-boot-starter</artifactId>
        </dependency>
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>druid-spring-boot-starter</artifactId>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.9.1</version>
        </dependency>
        <dependency>
            <groupId>javax.xml.bind</groupId>
            <artifactId>jaxb-api</artifactId>
            <version>2.4.0-b180830.0359</version>
        </dependency>
    </dependencies>
```

### 配置文件

```yml
server:
  port: 9194
spring:
  datasource:
    type: com.alibaba.druid.pool.DruidDataSource
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/meteo_oauth2?useSSL=false
    username: root
    password: 123456
  mybatis-plus:
    configuration:
      log-impl: org.apache.ibatis.logging.stdout.StdOutImpl
logging:
  level:
    org:
      springframework:
        security: trace
```

在这里，我们打开了日志功能，以实时监测授权服务的运行状况，便于开发调试。

### 实体类

应具有如下实体类，映射我们存储在数据库中的用户、权限列表和客户端。

```java
import lombok.Data;

@Data
public class User {
    private Integer id;
    private String name;
    private String password;
}
```

```Java
@Data
public class Authority {

    private Integer id;
    @NonNull
    private String authority;
}
```

```Java
@Data
public class Clients {
    private Integer id;
    private String clientId;
    private String secret;
    private String scope;
    private String authMethod;
    private String grantType;
    private String redirectUri;

    //客户端认证信息
    public static Clients from(RegisteredClient registeredClient){
        Clients clients = new Clients();

        clients.setClientId(registeredClient.getClientId());
        clients.setSecret(registeredClient.getClientSecret());

        clients.setRedirectUri(
                registeredClient.getRedirectUris().stream().findAny().get()
        );
        clients.setScope(
                registeredClient.getScopes().stream().findAny().get()
        );
        clients.setAuthMethod(
                registeredClient.getClientAuthenticationMethods().stream().findAny().get().getValue()
        );
        clients.setGrantType(
                registeredClient.getAuthorizationGrantTypes().stream().findAny().get().getValue()
        );

        return clients;
    }

    //客户端注册信息
    public static RegisteredClient from(Clients client) {
        return RegisteredClient.withId(String.valueOf(client.getId()))
                .clientId(client.getClientId())
                .clientSecret(client.getSecret())
                .scope(client.getScope())
                .redirectUri(client.getRedirectUri())
                .clientAuthenticationMethod(new ClientAuthenticationMethod(client.getAuthMethod()))
                .authorizationGrantType(new AuthorizationGrantType(client.getGrantType()))
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings.builder()
//            .accessTokenFormat(OAuth2TokenFormat.REFERENCE) // opaque
                        .accessTokenTimeToLive(Duration.ofHours(12)).build())
                .build();
    }
}
```

[此处](https://zhuanlan.zhihu.com/p/92051359)有关OAuth2的介绍，我们的项目使用到了授权码模式。在OAuth2协议中，如果客户端想实现授权认证，就需要向授权服务器注册一个客户端。客户端需要在注册时提供客户端标识符、客户端密钥、授权范围、授权类型和重定向URI等信息。我们这里免去了实现注册接口，直接在数据库中写入以实现客户端注册，因为我们只有一个客户端。

代码中的`RegisteredClient`对象表示了OAuth2客户端的注册信息，包含了这些信息的属性。`Clients`对象表示了OAuth2客户端的认证信息，也包含了这些信息的属性。

1. `from(RegisteredClient registeredClient)`方法：用于将`RegisteredClient`对象转换为`Clients`对象，以便处理OAuth2客户端认证相关的业务功能。
2. `from(Clients clients)`方法：用于将`Clients`对象转换为`RegisteredClient`对象，以便处理OAuth2客户端注册相关的业务功能。在OAuth2协议中，客户端需要将注册信息提交给服务器进行注册。`from(Clients clients)`方法将`Clients`对象中的客户端标识符、客户端密钥、授权范围、授权类型和重定向URI等信息转换为`RegisteredClient`对象的对应属性，以便进行客户端注册。

### 数据库表结构

|  id  | name |                           password                           |
| :--: | :--: | :----------------------------------------------------------: |
|  1   | root | $2a$12$qtGSN0BkoVGxgAO3O3UrEevCN54KcdIi2Vg1lig6HR2OpG9dZZhCG |

<p align="center">User表</p>

|  id  | authority |
| :--: | :-------: |
|  1   |   read    |

<p align="center">Authority表</p>

| id   | client_id        | secret                                                    | scope  | auth_method         | grant_type         | redirect_uri                     |
| ---- | ---------------- | --------------------------------------------------------- | ------ | ------------------- | ------------------ | -------------------------------- |
| 1    | meteo_client_one | $12$HSnlvcaZME8hXWzIb18LNe3HRaV5a7aiulmy19JUDyYi4sDfHUTLS | openid | client_secret_basic | authorization_code | http://localhost:9294/authorized |

<p align="center">Clients表</p>

### Mapper接口

```java
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.weather.entity.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper extends BaseMapper<User> {
}
```

```java
@Mapper
public interface AuthorityMapper extends BaseMapper<Authority> {
}
```

```Java
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.weather.entity.Clients;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface ClientsMapper extends BaseMapper<Clients> {
}
```

### Repository存储库

```Java
import com.weather.entity.Authority;
import com.weather.entity.User;

import java.util.List;

public interface UserRepository {
    User findUserByName(String name);
    List<Authority> getAuthoritiesByUserId(int userID);
}
```

```Java
@Service
@RequiredArgsConstructor
public class UserRepositoryImpl implements UserRepository {
    private final UserMapper userMapper;
    private final AuthorityMapper authorityMapper;
    @Override
    public User findUserByName(String name) {
        return userMapper.selectOne(new QueryWrapper<User>()
                .eq("name",name)
                .select("id","name","password")
        );
    }

    @Override
    public List<Authority> getAuthoritiesByUserId(int userID) {
        return authorityMapper.selectList(new QueryWrapper<Authority>()
                .inSql("id","select authority_id from user_authority where user_id = " + userID)
                .select("id","authority"));
    }
}
```

应该有一个存储库可以使我们能够从数据库中根据用户名拿到用户信息，以及根据User的id来获取用户-权限映射关系，以获得权限id从而获取用户所拥有的权限。

```Java
import com.weather.entity.Clients;

public interface ClientsRepository {
    Clients findClientByClientID(String clientID);
    Clients findClientByID(Integer id);
}
```

```
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.weather.entity.Clients;
import com.weather.mapper.ClientsMapper;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class ClientsRepositoryImpl implements ClientsRepository{

    private final ClientsMapper clientsMapper;
    @Override
    public Clients findClientByClientID(String clientID) {
        Clients clients = clientsMapper.selectOne(new QueryWrapper<Clients>()
                .eq("client_id",clientID)
                .select(Clients.class,info->true)
        );
        System.out.println(clients.toString());
        return clients;
    }

    @Override
    public Clients findClientByID(Integer id) {
        return clientsMapper.selectOne(new QueryWrapper<Clients>()
                .eq("id",id)
                .select(Clients.class,info->true)
        );
    }
}
```

应该有一个存储库根据客户端ID获取客户端信息，同时根据id来获取一个客户端，供后续认证使用。

### Security

```Java
import com.weather.entity.Authority;
import com.weather.entity.User;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@AllArgsConstructor
public class SecurityUser implements UserDetails {

    private final User user;
    private final List<Authority> authorities;

    @Override
    public String getUsername() {
        return user.getName();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities.stream()
                .map(SecurityAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```

Spring Security 6自带一个接口UserDetails用以描述用户信息。我们原本可以借此直接在内存中创建一个用户，不过它是写死在内存中的。而一般情况下更倾向于使用数据库存储用户信息，因此需要自己实现一下该接口。通过该类，我们可以实现对用户名、密码的匹配，以及获取权限列表。

```Java
import com.weather.entity.Authority;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@AllArgsConstructor
public class SecurityAuthority implements GrantedAuthority {

    private final Authority authority;
    @Override
    public String getAuthority() {
        return authority.getAuthority();
    }
}
```

同样的，我们也可以直接在内存中创建权限信息，但是我们把权限存储在了数据库中，因此需要自己实现GrantedAuthority接口。

### Service

```java
import com.weather.entity.Authority;
import com.weather.repository.UserRepository;
import com.weather.security.SecurityUser;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class MybatisPlusUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var u = userRepository.findUserByName(username);
        List<Authority> authorities = userRepository.getAuthoritiesByUserId(u.getId());
        return Optional.ofNullable(u)
                .map(user ->new SecurityUser(user,authorities))
                .orElseThrow(()->new UsernameNotFoundException("Username not fount " + username));
    }
}
```

`UserDetailsService`是Spring Security中的一个接口，用于从外部数据源中获取用户信息，它通常和UserDetails一起使用。这里我们以刚刚写好的存储库作为数据源。通过此类，我们可以载入用户。

```Java
import com.weather.entity.Clients;
import com.weather.mapper.ClientsMapper;
import com.weather.repository.ClientsRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional//标记该类为事务处理
@AllArgsConstructor
public class CustomClientService implements RegisteredClientRepository {

    private final ClientsMapper clientsMapper;
    private final ClientsRepository clientsRepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        clientsMapper.insert(Clients.from(registeredClient));
    }

    @Override
    public RegisteredClient findById(String id) {
        return Clients.from(clientsRepository.findClientByID(Integer.valueOf(id)));
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return Clients.from(clientsRepository.findClientByClientID(clientId));
    }
}
```

`RegisteredClientRepository`是Spring Security中的一个接口，用于管理和存储OAuth2客户端的注册信息。在OAuth2协议中，客户端需要在注册时提供客户端标识符、客户端密钥、授权范围、授权类型和重定向URI等信息。`RegisteredClientRepository`接口定义了一些方法，用于管理和存储这些客户端注册信息，包括新增、删除、更新和查询等方法。

具体来说，`RegisteredClientRepository`接口定义了以下方法：

1. `findByClientId(String clientId)`：根据客户端标识符查找客户端注册信息。
2. `save(RegisteredClient registeredClient)`：保存客户端注册信息。
3. `deleteById(String id)`：根据客户端标识符删除客户端注册信息。
4. `findAll()`：查询所有的客户端注册信息。

在Spring Security中，通过实现`RegisteredClientRepository`接口，可以自定义OAuth2客户端注册信息的管理和存储方式。例如，可以实现一个`JdbcRegisteredClientRepository`，使用JDBC访问数据库，将客户端注册信息存储到数据库中。然后，可以将这个实现类注入到`ProviderSettings`中，用于管理OAuth2客户端的注册信息。

### Config

```Java
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.function.Consumer;

public class CustomRedirectUriValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

    @Override
    public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext context) {
        OAuth2AuthorizationCodeRequestAuthenticationToken a = context.getAuthentication();
        RegisteredClient registeredClient = context.getRegisteredClient();
        String uri = a.getRedirectUri();

        if (!registeredClient.getRedirectUris().contains(uri)) {
            var error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }
    }
}
```

`Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext>`是一个Java函数式接口，用于处理OAuth2授权码请求的认证上下文。在OAuth2协议中，客户端在获取访问令牌时，需要进行授权码模式认证，即向授权服务器请求授权码，并将授权码交换为访问令牌。在这个过程中，需要对请求进行认证和授权。

我们可以实现该接口进行自定义认证。在这里，实现了检查授权请求的重定向URI是否合法的功能，以保证请求的安全性。

在方法中，首先通过`context.getAuthentication()`方法获取到一个`OAuth2AuthorizationCodeRequestAuthenticationToken`对象，该对象表示OAuth2授权码请求的认证信息，包括请求的客户端ID、授权范围、重定向URI等信息。然后，通过`context.getRegisteredClient()`方法获取到这个客户端的注册信息，包括客户端ID、客户端密钥、授权范围、重定向URI等信息。

接着，代码判断授权请求中的重定向URI是否在客户端注册信息中，如果不在，则抛出一个`OAuth2AuthorizationCodeRequestAuthenticationException`异常，表示授权请求不合法。在抛出异常时，还会使用`OAuth2Error`对象表示错误的原因和描述。

```java
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

@Configuration
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http
                .csrf()
                .disable()
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationEndpoint(
                        a -> a.authenticationProviders(getAuthorizationEndpointProviders())
                )

                .oidc(Customizer.withDefaults());
        //自动重定向到默认登录页面
        http.exceptionHandling(
                e -> e.authenticationEntryPoint(
                        new LoginUrlAuthenticationEntryPoint("/login")
                )
        );
        return http.build();
    }

    private Consumer<List<AuthenticationProvider>> getAuthorizationEndpointProviders() {
        return providers -> {
            for (AuthenticationProvider p : providers) {
                if (p instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider x) {
                    x.setAuthenticationValidator(new CustomRedirectUriValidator());
                }
            }
        };
    }

    //默认表单登录
    @Bean
    @Order(2)
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
        http.formLogin()
             .and()
                .authorizeHttpRequests().anyRequest().authenticated();
        return http.build();
    }

    //开启加密
    @Bean
    public PasswordEncoder passwordEncoder(){
//        return NoOpPasswordEncoder.getInstance();
            return new BCryptPasswordEncoder();
    }

	//默认配置
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .build();
    }

    //http://localhost:9194/oauth2/jwks

    //生成jwt令牌的固定写法，无需维护
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    public static RSAKey generateRsa() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
    }

    static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    //为token自定义信息
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
        return  context -> {
            var authorities = context.getPrincipal().getAuthorities();
            context.getClaims().claim("authorities",authorities.stream().map(a -> a.getAuthority()).toList());
        };
    }
}
```

配置一个安全过滤链。

方法`asSecurityFilterChain()`，用于创建一个Spring Security过滤器链，用于处理OAuth2授权和认证请求。具体来说，这个方法使用了Spring Security OAuth2的一些配置和默认值，实现了以下功能：

1. 应用默认的OAuth2安全配置：通过调用`OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)`方法，应用Spring Security OAuth2的默认安全配置，包括添加OAuth2认证和授权相关的过滤器和拦截器等。
2. 禁用CSRF保护：通过调用`http.csrf().disable()`方法，禁用了CSRF保护，以便进行OAuth2授权和认证请求。
3. 配置授权端点：通过调用`http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).authorizationEndpoint(a -> a.authenticationProviders(getAuthorizationEndpointProviders()))`方法，配置了OAuth2授权端点的认证流程，包括使用`getAuthorizationEndpointProviders()`方法返回的认证提供者进行认证。
4. 配置OpenID Connect支持：通过调用`http.oidc(Customizer.withDefaults())`方法，配置了OpenID Connect支持。
5. 配置异常处理：通过调用`http.exceptionHandling(e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))`方法，配置了异常处理器，用于自动重定向到默认的登录页面，以便进行OAuth2认证。

方法`getAuthorizationEndpointProviders()`返回了一个`Consumer<List<AuthenticationProvider>>`类型的对象，用于对OAuth2授权端点的认证提供者进行自定义配置。具体来说，这个方法会遍历传入的认证提供者列表，找到`OAuth2AuthorizationCodeRequestAuthenticationProvider`类型的提供者，并为其设置一个自定义的重定向URI验证器`CustomRedirectUriValidator`。

在OAuth2授权码模式中，客户端使用授权码向授权服务器请求访问令牌。在请求授权码时，客户端需要提供一个重定向URI，以便授权服务器将授权码返回给客户端。重定向URI需要与客户端注册信息中的重定向URI相匹配，以确保请求的安全性。

在这个方法中，通过设置自定义的重定向URI验证器`CustomRedirectUriValidator`，可以对授权请求的重定向URI进行自定义的验证。

## 自定义客户端

创建一个新的服务：OAuth2CustomClient-Service用以自定义客户端。我们的客户端由前后端共同构成，这里只描述后端部分。

### 统一授权码获取结果

```Java
public interface ResultCode {
    Integer SUCCESS = 1;
    Integer Fail = 0;
}
```

```Java
import lombok.Data;

@Data
public class Result {
    private Integer success;
    private String code;

    public static Result success(String code){
        Result result = new Result();
        result.setSuccess(ResultCode.SUCCESS);
        result.setCode(code);
        return result;
    }

    public static Result fail(){
        Result result = new Result();
        result.setSuccess(ResultCode.Fail);
        return result;
    }
}
```

### HTTP端点

定义我们的重定向请求，为了便于测试，目前使用统一的code_challenge和verifier。

```java
import com.weather.utils.Result;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ClientController {

    // 测试该链接以获取code
    // http://localhost:9194/oauth2/authorize?response_type=code&client_id=meteo_client_one&scope=openid&redirect_uri=http://localhost:9294/authorized&code_challenge=QYPAZ5NU8yvtlQ9erXrUYR-T5AGCjCF47vN-KsaI2A8&code_challenge_method=S256
    @GetMapping("/authorized")
    public Result authorized(@RequestParam("code") String code){

        return code != null ? Result.success(code):Result.fail();
    }
    //使用POST请求，将新code替换以下code，以获取令牌体
    //http://localhost:9194/oauth2/token?client_id=meteo_client_one&redirect_uri=http://localhost:9294/authorized&grant_type=authorization_code&code=cgbBle6_tKq7BEWtDA3gRBacB_X3MsCN4-XI83kDm-ltgJ4HbJ0ERFAIssrh0g21O9a3M5AuNi2OQ_iIxL2_Gh7vfTiv561J0cBX4lOIQj5Xs3YCYcV3HVxDBB-4bFfC&code_verifier=qPsH306-ZDDaOE8DFzVn05TkN3ZZoVmI_6x4LsVglQI
    //获取access_token 放置于该请求的头部，以获取资源服务
}
```

应该首先在浏览器登录：http://localhost:9194/oauth2/authorize?response_type=code&client_id=meteo_client_one&scope=openid&redirect_uri=http://localhost:9294/authorized&code_challenge=QYPAZ5NU8yvtlQ9erXrUYR-T5AGCjCF47vN-KsaI2A8&code_challenge_method=S256

以获取code。code只能使用一次。剩余接口详情请在Apifox中团队接口查看。

## 数据分析服务

此服务包括：

- 调用数据获取程序（可考虑使用WebFlux，在服务内部定义一些HTPP端点调用实现）
- 基于Redis及MySQL的数据查询
- Python脚本调用
  - 相关系数矩阵
  - 数据清洗（待完成）
  - 天气数据预报（待完成）
- 获取清洗好的数据（待完成）

建立一个名为Meteo-Process-Resource的服务。

### 核心依赖

引入核心依赖

```xml
<dependencies>
    <dependency>
        <groupId>com.baomidou</groupId>
        <artifactId>mybatis-plus-boot-starter</artifactId>
    </dependency>
    <dependency>
        <groupId>com.alibaba</groupId>
        <artifactId>druid-spring-boot-starter</artifactId>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt</artifactId>
        <version>0.9.1</version>
    </dependency>
    <dependency>
        <groupId>javax.xml.bind</groupId>
        <artifactId>jaxb-api</artifactId>
        <version>2.3.1</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-redis</artifactId>
    </dependency>
    <dependency>
        <groupId>org.apache.commons</groupId>
        <artifactId>commons-pool2</artifactId>
    </dependency>
    <dependency>
        <groupId>org.json</groupId>
        <artifactId>json</artifactId>
        <version>20220320</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
    </dependency>
    <dependency>
        <groupId>com.alibaba.fastjson2</groupId>
        <artifactId>fastjson2</artifactId>
        <version>2.0.25</version>
    </dependency>
</dependencies>
```

### 配置文件

```yml
server:
  port: 9394

spring:
  datasource:
    type: com.alibaba.druid.pool.DruidDataSource
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/meteo_data?useSSL=false
    username: root
    password: 123456
  data:
    redis:
      database: 15
      host: 81.71.161.47
      port: 6379
      password: 123456
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:9090
mybatis-plus:
  configuration:
    log-impl: org.apache.ibatis.logging.stdout.StdOutImpl
jwksUri: http://localhost:9194/oauth2/jwks
```

### 实体类

```Java
import lombok.Data;

@Data
public class Station {
    private Integer id;
    private String station;
    private String name;
}
```

```Java
import lombok.Data;

@Data
public class StationDate {
    private Integer id;
    private String date;
    private String station;
}
```

```Java
import com.baomidou.mybatisplus.extension.activerecord.Model;


public class Meteorology extends Model<Meteorology> {

    private Integer id;//不出现在查询结果中
    private String station;//不出现在查询结果中
    private String date;//不出现在查询结果中
    private String datetime;
    private String time;//不出现在查询结果中
    private String temperature;
    private String humidity;
    private String speed;
    private String direction;
    private String rain;
    private String sunlight;
    private String pm25;
    private String pm10;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getStation() {
        return station;
    }

    public void setStation(String station) {
        this.station = station;
    }

    public String getDate() {
        return date;
    }

    public void setDate(String date) {
        this.date = date;
    }

    public String getDatetime() {
        return datetime;
    }

    public void setDatetime(String datetime) {
        this.datetime = datetime;
    }

    public String getTime() {
        return time;
    }

    public void setTime(String time) {
        this.time = time;
    }

    public String getTemperature() {
        return temperature;
    }

    public void setTemperature(String temperature) {
        this.temperature = temperature;
    }

    public String getHumidity() {
        return humidity;
    }

    public void setHumidity(String humidity) {
        this.humidity = humidity;
    }

    public String getSpeed() {
        return speed;
    }

    public void setSpeed(String speed) {
        this.speed = speed;
    }

    public String getDirection() {
        return direction;
    }

    public void setDirection(String direction) {
        this.direction = direction;
    }

    public String getRain() {
        return rain;
    }

    public void setRain(String rain) {
        this.rain = rain;
    }

    public String getSunlight() {
        return sunlight;
    }

    public void setSunlight(String sunlight) {
        this.sunlight = sunlight;
    }

    public String getPm25() {
        return pm25;
    }

    public void setPm25(String pm25) {
        this.pm25 = pm25;
    }

    public String getPm10() {
        return pm10;
    }

    public void setPm10(String pm10) {
        this.pm10 = pm10;
    }


    @Override
    public String toString() {
        return "[" +
                "\"" + datetime + "\"," +
                "\"" + temperature + "\"," +
                "\"" + humidity + "\"," +
                "\"" + speed + "\"," +
                "\"" + direction + "\"," +
                "\"" + rain + "\"," +
                "\"" + sunlight + "\"," +
                "\"" + pm25 + "\"," +
                "\"" + pm10 + "\"" +
                "]";
    }


}
```

### 数据库表结构

```sql
DROP TABLE IF EXISTS `station`;
CREATE TABLE `station`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `station` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '气象站编号',
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '气象站名称',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

SET FOREIGN_KEY_CHECKS = 1;
```

```sql
DROP TABLE IF EXISTS `station_date`;
CREATE TABLE `station_date`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `date` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `station` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 3 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

SET FOREIGN_KEY_CHECKS = 1;
```

```sql
DROP TABLE IF EXISTS `m2_403_weather_2023`;
CREATE TABLE `m2_403_weather_2023`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `station` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL,
  `date` date NULL DEFAULT NULL,
  `datetime` datetime(0) NULL DEFAULT NULL,
  `time` time(0) NULL DEFAULT NULL,
  `temperature` float NULL DEFAULT NULL,
  `humidity` float NULL DEFAULT NULL,
  `speed` float NULL DEFAULT NULL,
  `direction` float NULL DEFAULT NULL,
  `rain` float NULL DEFAULT NULL,
  `sunlight` float NULL DEFAULT NULL,
  `pm25` float NULL DEFAULT NULL,
  `pm10` float NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `index_station_date`(`station`, `date`, `datetime`, `time`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 25920 CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

SET FOREIGN_KEY_CHECKS = 1;
```

### 统一响应结果

```Java
public interface Result {

}
```

```Java
public interface ResultCode {
    public static int SUCCESS = 1;//成功
    public static int FAIL = 0;//失败
}
```

```java
import lombok.Data;

@Data
public class StationResult implements Result{
    private int success;
    private Object station;

    public static StationResult success(Object station){
        StationResult stationResult = new StationResult();
        stationResult.setSuccess(ResultCode.SUCCESS);
        stationResult.setStation(station);
        return stationResult;
    }

    public static StationResult fail(){
        StationResult stationResult = new StationResult();
        stationResult.setSuccess(ResultCode.FAIL);
        return stationResult;
    }

}
```

```java
import lombok.Data;

@Data
public class StationDateResult implements Result{
    private int success;
    private Object date;

    public static StationDateResult success(Object date){
        StationDateResult stationDateResult = new StationDateResult();
        stationDateResult.setSuccess(ResultCode.SUCCESS);
        stationDateResult.setDate(date);
        return stationDateResult;
    }

    public static StationDateResult fail(){
        StationDateResult stationDateResult = new StationDateResult();
        stationDateResult.setSuccess(ResultCode.FAIL);
        return stationDateResult;
    }
}
```

```java
import lombok.Data;

@Data
public class MeteorologyResult {
    private int success;
    private String station;
    private Object data;

    public static MeteorologyResult success(String station, Object data){
        MeteorologyResult meteorologyResult = new MeteorologyResult();
        meteorologyResult.setSuccess(ResultCode.SUCCESS);
        meteorologyResult.setStation(station);
        meteorologyResult.setData(data);
        return meteorologyResult;
    }

    public static MeteorologyResult fail(){
        MeteorologyResult meteorologyResult = new MeteorologyResult();
        meteorologyResult.setSuccess(ResultCode.FAIL);
        return meteorologyResult;
    }
}
```

### Mapper接口

应该具有MySQL和Redis双重的查询接口。

#### MySQL

表名设计为：”气象站编号“+weather+”年份“，也就是说，一年一表。例如：

```
m2_403_weather_2023
```

- 此处已经考虑到并实现了跨年查询的情况
- 在Redis-to-MySQL脚本中已经实现了索引植入，保证了查询速度

```java
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.weather.entity.Station;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface StationMapper extends BaseMapper<Station> {
    
}
```

```java
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.weather.entity.StationDate;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface StationDateMapper extends BaseMapper<StationDate> {

}
```

```Java
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.weather.entity.Meteorology;
import org.apache.ibatis.annotations.*;

import java.util.List;

@Mapper
public interface MeteorologyMySQLMapper extends BaseMapper<Meteorology> {

    //转义：&gt;为 >  &lt;为 <

    @Select("<script>" +
            "SELECT datetime" +
            "<if test=\"which.contains('1'.toString())\">, temperature</if>" +
            "<if test=\"which.contains('2'.toString())\">, humidity</if>" +
            "<if test=\"which.contains('3'.toString())\">, speed</if>" +
            "<if test=\"which.contains('4'.toString())\">, direction</if>" +
            "<if test=\"which.contains('5'.toString())\">, rain</if>" +
            "<if test=\"which.contains('6'.toString())\">, sunlight</if>" +
            "<if test=\"which.contains('7'.toString())\">, pm25</if>" +
            "<if test=\"which.contains('8'.toString())\">, pm10</if>" +
            " FROM ${datasource} WHERE DATE_FORMAT(dateTime, '%Y-%m-%d %H:%i:00') &gt;= '${startDateTime}' " +
            "  AND DATE_FORMAT(dateTime, '%Y-%m-%d %H:%i:00') &lt;= '${endDateTime}' " +
            "  AND DATE_FORMAT(dateTime, '%s') = '00'" +
            "</script>")
    @Results( id = "SQLResults",
            value =
            {
                @Result(column = "datetime",property = "datetime"),
                @Result(column = "humidity",property = "humidity"),
                @Result(column = "speed",property = "speed"),
                @Result(column = "direction",property = "direction"),
                @Result(column = "rain",property = "rain"),
                @Result(column = "sunlight",property = "sunlight"),
                @Result(column = "pm25",property = "pm25"),
                @Result(column = "pm10",property = "pm10")
            }
    )
    List<Meteorology> selectMeteorologyHour(@Param("datasource") String datasource,
                                         @Param("startDateTime") String startDateTime,
                                         @Param("endDateTime") String endDateTime,
                                         @Param("which") String which);

    @Select("<script>" +
            "SELECT time" +
            "<if test=\"which.contains('1'.toString())\">, temperature</if>" +
            "<if test=\"which.contains('2'.toString())\">, humidity</if>" +
            "<if test=\"which.contains('3'.toString())\">, speed</if>" +
            "<if test=\"which.contains('4'.toString())\">, direction</if>" +
            "<if test=\"which.contains('5'.toString())\">, rain</if>" +
            "<if test=\"which.contains('6'.toString())\">, sunlight</if>" +
            "<if test=\"which.contains('7'.toString())\">, pm25</if>" +
            "<if test=\"which.contains('8'.toString())\">, pm10</if>" +
            " FROM ${datasource} WHERE DATE_FORMAT(dateTime, '%Y-%m-%d %H:%i:%s') &gt;= '${startDateTime}' " +
            "  AND DATE_FORMAT(dateTime, '%Y-%m-%d %H:%i:%s') &lt;= '${endDateTime}' " +
            "  AND DATE_FORMAT(dateTime, '%i') = '00'" +"  AND DATE_FORMAT(dateTime, '%s') = '00'" +
            "</script>")
    @ResultMap(value = "SQLResults")
    List<Meteorology> selectMeteorologyDay(@Param("datasource") String datasource,
                                           @Param("startDateTime") String startDateTime,
                                           @Param("endDateTime") String endDateTime,
                                           @Param("which") String which);

    @Select("<script>" +
            "SELECT datetime" +
            "<if test=\"which.contains('1'.toString())\">, temperature</if>" +
            "<if test=\"which.contains('2'.toString())\">, humidity</if>" +
            "<if test=\"which.contains('3'.toString())\">, speed</if>" +
            "<if test=\"which.contains('4'.toString())\">, direction</if>" +
            "<if test=\"which.contains('5'.toString())\">, rain</if>" +
            "<if test=\"which.contains('6'.toString())\">, sunlight</if>" +
            "<if test=\"which.contains('7'.toString())\">, pm25</if>" +
            "<if test=\"which.contains('8'.toString())\">, pm10</if>" +
            " FROM ${datasource} WHERE DATE_FORMAT(dateTime, '%Y-%m-%d %H:%i:%s') &gt;= '${startDateTime}' " +
            "  AND DATE_FORMAT(dateTime, '%Y-%m-%d %H:%i:%s') &lt;= '${endDateTime}' " +
            "  AND DATE_FORMAT(dateTime, '%H') = '08'" +
            "  AND DATE_FORMAT(dateTime, '%i') = '00'" +
            "  AND DATE_FORMAT(dateTime, '%s') = '00'" +
            "</script>")
    @ResultMap(value = "SQLResults")
    List<Meteorology> selectMeteorologyDate(@Param("datasource") String datasource,
                                           @Param("startDateTime") String startDateTime,
                                           @Param("endDateTime") String endDateTime,
                                           @Param("which") String which);

    @Select("<script>" +
            "SELECT datetime" +
            "<if test=\"which.contains('1'.toString())\">, temperature</if>" +
            "<if test=\"which.contains('2'.toString())\">, humidity</if>" +
            "<if test=\"which.contains('3'.toString())\">, speed</if>" +
            "<if test=\"which.contains('4'.toString())\">, direction</if>" +
            "<if test=\"which.contains('5'.toString())\">, rain</if>" +
            "<if test=\"which.contains('6'.toString())\">, sunlight</if>" +
            "<if test=\"which.contains('7'.toString())\">, pm25</if>" +
            "<if test=\"which.contains('8'.toString())\">, pm10</if>" +
            " FROM ${datasourceStartDate} WHERE DATE_FORMAT(dateTime, '%Y-%m-%d %H:%i:%s') &gt;= '${startDateTime}' " +
            "  AND DATE_FORMAT(dateTime, '%Y-%m-%d %H:%i:%s') &lt;= '${endDateTime}' " +
            "  AND DATE_FORMAT(dateTime, '%H') = '08'" +
            "  AND DATE_FORMAT(dateTime, '%i') = '00'" +
            "  AND DATE_FORMAT(dateTime, '%s') = '00'" +
            "UNION " +
            "SELECT time" +
            "<if test=\"which.contains('1'.toString())\">, temperature</if>" +
            "<if test=\"which.contains('2'.toString())\">, humidity</if>" +
            "<if test=\"which.contains('3'.toString())\">, speed</if>" +
            "<if test=\"which.contains('4'.toString())\">, direction</if>" +
            "<if test=\"which.contains('5'.toString())\">, rain</if>" +
            "<if test=\"which.contains('6'.toString())\">, sunlight</if>" +
            "<if test=\"which.contains('7'.toString())\">, pm25</if>" +
            "<if test=\"which.contains('8'.toString())\">, pm10</if>" +
            " FROM ${datasourceEndDate} WHERE DATE_FORMAT(dateTime, '%Y-%m-%d %H:%i:%s') &gt;= '${startDateTime}' " +
            "  AND DATE_FORMAT(dateTime, '%Y-%m-%d %H:%i:%s') &lt;= '${endDateTime}' " +
            "  AND DATE_FORMAT(dateTime, '%H') = '08'" +
            "  AND DATE_FORMAT(dateTime, '%i') = '00'" +
            "  AND DATE_FORMAT(dateTime, '%s') = '00'" +
            "</script>")
    @ResultMap(value = "SQLResults")
    List<Meteorology> selectMeteorologyDateInOtherYear(@Param("datasourceStartDate") String dataSourceStartDate,
                                            @Param("datasourceEndDate") String dataSourceEndDate,
                                            @Param("startDateTime") String startDateTime,
                                            @Param("endDateTime") String endDateTime,
                                            @Param("which") String which);

    @Select("<script>" +
            "SELECT datetime, temperature, humidity, speed, direction, rain, sunlight, pm25, pm10 " +
            "FROM ${datasource} " +
            "WHERE station = '${station}' " +
            "AND DATE_FORMAT(date, '%Y-%m-%d') &gt;= '${startDate}' " +
            "<if test=\"endDate != null\">AND DATE_FORMAT(date, '%Y-%m-%d') &lt;= '${endDate}' </if>" +
            "<if test=\"startTemperature != null\">AND temperature &gt;= '${startTemperature}' </if>" +
            "<if test=\"endTemperature != null\">AND temperature &lt;= '${endTemperature}' </if>" +
            "<if test=\"startHumidity != null\">AND humidity &gt;= '${startHumidity}' </if>" +
            "<if test=\"endHumidity != null\">AND humidity &lt;= '${endHumidity}' </if>" +
            "<if test=\"startSpeed != null\">AND speed &gt;= '${startSpeed}' </if>" +
            "<if test=\"endSpeed != null\">AND speed &lt;= '${endSpeed}' </if>" +
            "<if test=\"startDirection != null\">AND direction &gt;= '${startDirection}' </if>" +
            "<if test=\"endDirection != null\">AND direction &lt;= '${endDirection}' </if>" +
            "<if test=\"startRain != null\">AND rain &gt;= '${startRain}' </if>" +
            "<if test=\"endRain != null\">AND rain &lt;= '${endRain}' </if>" +
            "<if test=\"startSunlight != null\">AND sunlight &gt;= '${startSunlight}' </if>" +
            "<if test=\"endSunlight != null\">AND sunlight &lt;= '${endSunlight}' </if>" +
            "<if test=\"startPm25 != null\">AND pm25 &gt;= '${startPm25}' </if>" +
            "<if test=\"endPm25 != null\">AND pm25 &lt;= '${endPm25}' </if>" +
            "<if test=\"startPm10 != null\">AND pm10 &gt;= '${startPm10}' </if>" +
            "<if test=\"endPm10 != null\">AND pm10 &lt;= '${endPm10}' </if>" +
            "</script>")
    @ResultMap(value = "SQLResults")
    List<Meteorology> selectMeteorologyComplex(
            @Param("datasource") String datasource,
            @Param("station") String station,
            @Param("startDate") String startDate,
            @Param("endDate") String endDate,
            @Param("startTemperature") String startTemperature,
            @Param("endTemperature") String endTemperature,
            @Param("startHumidity") String startHumidity,
            @Param("endHumidity") String endHumidity,
            @Param("startSpeed") String startSpeed,
            @Param("endSpeed") String endSpeed,
            @Param("startDirection") String startDirection,
            @Param("endDirection") String endDirection,
            @Param("startRain") String startRain,
            @Param("endRain") String endRain,
            @Param("startSunlight") String startSunlight,
            @Param("endSunlight") String endSunlight,
            @Param("startPm25") String startPm25,
            @Param("endPm25") String endPm25,
            @Param("startPm10") String startPm10,
            @Param("endPm10") String endPm10
    );
}
```

#### Redis

Redis采用zSet有序集合，以UNIX时间序列作为分数。

键名设计为："气象站编号"+data+"年月日"。例如：

```
m2_403_data_2023-04-01
```

一个数据样例为：

```
[
  "00:00:00",
  "20",
  "43",
  "3",
  "270",
  "1",
  "440",
  "13",
  "39"
]
```

其score为：

```
1680278400
```

```Java
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface MeteorologyMapper  {

    List<String[]> getMeteorologyDataByTime(String key,long startTimestamp, long endTimestamp);
    List<String[]> getMeteorologyDataByDate(String station,long startTimestamp, long endTimestamp, String start_date, String end_date);
}
```

```Java
import com.fasterxml.jackson.databind.ObjectMapper;
import com.weather.mapper.Redis.meteorology.MeteorologyMapper;
import lombok.AllArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;


@Repository
@AllArgsConstructor
public class MeteorologyMapperImpl implements MeteorologyMapper {
    
    private final RedisTemplate<String, String> redisTemplate;

    // 创建 ObjectMapper 实例，用于序列化和反序列化 JSON
    ObjectMapper objectMapper = new ObjectMapper();
    // 创建一个列表，用于保存获取到的气象数据

    /**
     * 根据小时获取气象数据
     * @param key Redis 中的键名
     * @param startTimestamp 开始时间戳（单位：秒）
     * @param endTimestamp 结束时间戳（单位：秒）
     * @return 返回气象数据的列表，每个元素是一个字符串数组
     */
    @Override
    public List<String[]> getMeteorologyDataByTime(String key, long startTimestamp, long endTimestamp) {
        return redisTemplate.execute(new RedisCallback<List<String[]>>() {
            @Override
            public List<String[]> doInRedis(RedisConnection connection) throws DataAccessException {
                // 获取 Redis 中指定范围内的有序集合
                Set<byte[]> set = connection.zRangeByScore(key.getBytes(), startTimestamp, endTimestamp);
                List<String[]> dataList = new ArrayList<>();
                for (byte[] data : set) {
                    try {
                        // 将 JSON 字节数组转换为字符串数组，并添加到 dataList 列表中
                        String[] dataArray = objectMapper.readValue(data, String[].class);
                        dataList.add(dataArray);
                    } catch (IOException e) {
                        // 如果转换出错，抛出 RuntimeException 异常
                        throw new RuntimeException(e);
                    }
                }
                if (!dataList.isEmpty()) {
                    return dataList;
                } else {
                    return null;
                }
            }
        });
    }

    @Override
    public List<String[]> getMeteorologyDataByDate(String station, long startTimestamp, long endTimestamp, String start_date, String end_date) {
        return redisTemplate.execute(new RedisCallback<List<String[]>>() {
            @Override
            public List<String[]> doInRedis(RedisConnection connection) throws DataAccessException {
                List<String[]> dataList = new ArrayList<>();
                for (String date : datesBetween(start_date, end_date)) {
                    String key = station + "_data_" + date;
                    // 获取 Redis 中指定范围内的有序集合
                    Set<byte[]> set = connection.zRangeByScore(key.getBytes(), startTimestamp, endTimestamp);
                    if (!set.isEmpty()){
                        for (byte[] data : set) {
                            try {
                                // 将 JSON 字节数组转换为字符串数组，并添加到 dataList 列表中
                                String[] dataArray = objectMapper.readValue(data, String[].class);
                                dataList.add(dataArray);
                            } catch (IOException e) {
                                // 如果转换出错，抛出 RuntimeException 异常
                                throw new RuntimeException(e);
                            }
                        }
                    }else {
                        dataList.clear();
                    }
                }
                return dataList;
            }
        });
    }

    public List<String> datesBetween(String startDateStr, String endDateStr) {
        LocalDate startDate = LocalDate.parse(startDateStr);
        LocalDate endDate = LocalDate.parse(endDateStr);
        List<String> dates = new ArrayList<>();
        while (!startDate.isAfter(endDate)) {
            dates.add(startDate.toString());
            startDate = startDate.plus(1, ChronoUnit.DAYS);
        }
        return dates;
    }
}
```

### Service

#### **Station相关**

```Java
import com.weather.utils.StationResult;

public interface StationService {
    StationResult getStationInfo();
}
```

```java
import com.weather.utils.StationDateResult;

public interface StationDateService {
    StationDateResult getStationDateByStationId(String station);
}
```

**实现类**

```java
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.weather.entity.Station;
import com.weather.mapper.MySQL.station.StationMapper;
import com.weather.service.station.StationService;
import com.weather.utils.StationResult;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@AllArgsConstructor
public class StationServiceImpl implements StationService {
    private final StationMapper stationMapper;

    @Override
    public StationResult getStationInfo() {

        List<Map<String, Object>> stationList = stationMapper.selectMaps(new QueryWrapper<Station>().select("station", "name"));
        return !stationList.isEmpty() ? StationResult.success(stationList):StationResult.fail();

    }
}
```

```Java
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.weather.entity.StationDate;
import com.weather.mapper.MySQL.station.StationDateMapper;
import com.weather.service.station.StationDateService;
import com.weather.utils.StationDateResult;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class StationDateServiceImpl implements StationDateService {
    private final StationDateMapper stationDateMapper;

    @Override
    public StationDateResult getStationDateByStationId(String station) {
        QueryWrapper<StationDate> queryWrapper = Wrappers.<StationDate>query()
                .eq("station", station)
                .select("date");
        List<Map<String, Object>> stationDate = stationDateMapper.selectMaps(queryWrapper);
        List<String> dateList = stationDate.stream()
                .map(map -> map.get("date").toString())
                .collect(Collectors.toList());
        return !dateList.isEmpty() ? StationDateResult.success(dateList) : StationDateResult.fail();
    }
}
```

#### Meteo相关

```Java
import com.weather.utils.MeteorologyResult;

public interface MeteorologyService {

    MeteorologyResult getMeteorologyByHour(String station,String date,String hour,String which);
    MeteorologyResult getMeteorologyByDay(String station,String date,String which);
    MeteorologyResult getMeteorologyByDate(String station,String start_date,String end_date,String which);
    MeteorologyResult corrcoefDate(String station,String start_date,String end_date,String correlation);

    MeteorologyResult getComplexMeteorology(String station,
                                            String start_date,
                                            String end_date,
                                            String start_temperature,
                                            String end_temperature,
                                            String start_humidity,
                                            String end_humidity,
                                            String start_speed,
                                            String end_speed,
                                            String start_direction,
                                            String end_direction,
                                            String start_rain,
                                            String end_rain,
                                            String start_sunlight,
                                            String end_sunlight,
                                            String start_pm25,
                                            String end_pm25,
                                            String start_pm10,
                                            String end_pm10);

}
```

实现类可以直接看项目源码，有详细的注释。

## 数据获取程序（待补全）

从数据存储服务器中获取数据，以rdb形式持久化存储至redis中。

通过不同的code，数据存储服务器会识别属于哪一种请求，同样作为接受数据的客户端，也应该根据不同的code，识别为不同的响应。此处应遵循协议3接口。

### **添加核心依赖**

```xml
<dependencies>
    <dependency>
        <groupId>io.netty</groupId>
        <artifactId>netty-all</artifactId>
    </dependency>
    <dependency>
        <groupId>com.google.code.gson</groupId>
        <artifactId>gson</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-redis</artifactId>
    </dependency>
</dependencies>
```

### 配置文件

```yml
udp:
  remote:
    host: 127.0.0.1
    port: 9092
spring:
  data:
    redis:
      database: 15
      host: 81.71.161.47
      port: 6379
      password: 123456
```

### **实体类**

应该建立请求参数的实体类，便于转换成Json格式请求

```java
import lombok.Data;

@Data
public class GetToken {
    int code;
    String name;
    String password;

    public GetToken(int code, String name, String password) {
        this.code = code;
        this.name = name;
        this.password = password;
    }
}
```

```Java
import lombok.Data;

@Data
public class VoidToken {
    int code;
    String token;

    public VoidToken(int code, String token) {
        this.code = code;
        this.token = token;
    }
}
```

```Java
import lombok.Data;

@Data
public class GetAllStationCode {
    int code;
    String token;

    public GetAllStationCode(int code, String token) {
        this.code = code;
        this.token = token;
    }
}
```

```Java
import lombok.Data;

@Data
public class GetStationDateRange {
    int code;
    String token;
    String station;

    public GetStationDateRange(int code, String token, String station) {
        this.code = code;
        this.token = token;
        this.station = station;
    }
}
```

```java
import lombok.Data;

@Data
public class GetMeteoData {
    int code;
    String token;
    String start;
    String end;

    public GetMeteoData(int code, String token, String start, String end) {
        this.code = code;
        this.token = token;
        this.start = start;
        this.end = end;
    }
}
```

### Client

创建一个UDP客户端

```java
import com.weather.handler.UDPClientHandler;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.net.InetSocketAddress;

@Component
public class UDPClient {
    private final Bootstrap bootstrap;
    private final EventLoopGroup eventLoopGroup;
    private final Channel channel;
    private final InetSocketAddress serverAddress;
    private final UDPClientHandler udpClientHandler;

    public UDPClient(Environment environment, UDPClientHandler udpClientHandler) {
        this.eventLoopGroup = new NioEventLoopGroup();
        this.bootstrap = new Bootstrap();
        this.serverAddress = new InetSocketAddress(
                environment.getProperty("udp.remote.host"),
                environment.getProperty("udp.remote.port", Integer.class)
        );
        this.udpClientHandler = udpClientHandler;
        this.channel = bootstrap.group(eventLoopGroup)
                .channel(NioDatagramChannel.class)
                .handler(new ChannelInitializer<DatagramChannel>() {
                    @Override
                    protected void initChannel(DatagramChannel ch) {
                        ChannelPipeline pipeline = ch.pipeline();
                        pipeline.addLast(udpClientHandler);
                    }
                })
                .bind(0)
                .syncUninterruptibly()
                .channel();
        // 打印日志信息
        if (channel.isActive()) {
            System.out.println("UDP client connected to server " + serverAddress.getHostString() + ":" + serverAddress.getPort());
        } else {
            System.out.println("UDP client failed to connect to server " + serverAddress.getHostString() + ":" + serverAddress.getPort());
        }
    }

    public void send(String message) throws Exception {
        byte[] data = message.getBytes();
        channel.writeAndFlush(new DatagramPacket(Unpooled.copiedBuffer(data), serverAddress)).sync();
    }

    public void shutdown() {
        eventLoopGroup.shutdownGracefully();
    }

    @Bean
    public UDPClientHandler udpClientHandler() {
        return new UDPClientHandler();
    }
}
```

### Service

令牌获取与令牌废弃，此处直接在内存中创建用户，仅为测试使用，真实情况应为其创建HTTP端点，传入数据分析服务用户的信息，以此作为用户。

```
import com.fasterxml.jackson.databind.ObjectMapper;
import com.weather.client.UDPClient;
import com.weather.entity.request.GetToken;
import com.weather.entity.request.VoidToken;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class TokenService {
    private final UDPClient udpClient;

    public void getToken() throws Exception {
        int code = 1;
        String name = "user";
        String password = "123456";

        GetToken getToken = new GetToken(code,name,password);
        ObjectMapper mapper = new ObjectMapper();
        String getTokenRequest = mapper.writeValueAsString(getToken);
        udpClient.send(getTokenRequest);
    }

    public void voidToken() throws Exception {
        int code = 3;
        String token = "asdfghjklzxcvbnm";

        VoidToken voidToken = new VoidToken(code,token);
        ObjectMapper mapper = new ObjectMapper();
        String voidTokenRequest = mapper.writeValueAsString(voidToken);
        udpClient.send(voidTokenRequest);
    }
}
```

此处仅为模拟使用令牌发送请求获取数据

```
import com.fasterxml.jackson.databind.ObjectMapper;
import com.weather.client.UDPClient;
import com.weather.entity.request.GetAllStationCode;
import com.weather.entity.request.GetMeteoData;
import com.weather.entity.request.GetStationDateRange;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class MeteoDataService {
    private final UDPClient udpClient;

    public void getAllStationCode() throws Exception {
        int code = 5;
        String token = "asdfghjklzxcvbnm";

        GetAllStationCode getAllStationCode = new GetAllStationCode(code,token);
        ObjectMapper mapper = new ObjectMapper();
        String getAllStationCodeRequest = mapper.writeValueAsString(getAllStationCode);
        udpClient.send(getAllStationCodeRequest);
    }

    public void getAllStationDataRange() throws Exception {
        int code = 7;
        String token = "asdfghjklzxcvbnm";
        String station = "m2_403";

        GetStationDateRange getStationDateRange = new GetStationDateRange(code,token,station);
        ObjectMapper mapper = new ObjectMapper();
        String getStationDataRangeRequest = mapper.writeValueAsString(getStationDateRange);
        udpClient.send(getStationDataRangeRequest);
    }

    public void getMeteoData() throws Exception {
        int code = 9;
        String token = "asdfghjklzxcvbnm";
        String start = "2023-04-01";
        String end = "2023-04-03";

        GetMeteoData getMeteoData = new GetMeteoData(code,token,start,end);
        ObjectMapper mapper = new ObjectMapper();
        String getMeteoDataRequest = mapper.writeValueAsString(getMeteoData);
        udpClient.send(getMeteoDataRequest);
    }
}
```

### Handler

集中管理响应，根据不同的响应码完成对应的事件。

```
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.weather.handler.response.GetTokenHandler;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.DatagramPacket;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.ByteBuffer;

@Component
public class UDPClientHandler extends SimpleChannelInboundHandler<DatagramPacket> {

    @Autowired
    private GetTokenHandler getTokenHandler;
    @Override
    protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket packet) {
        ByteBuf content = packet.content();
        ByteBuffer byteBuffer = content.nioBuffer();
        byte[] bytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(bytes);
        String response = new String(bytes);
        Gson gson = new Gson();
        JsonElement jsonElement = gson.fromJson(response, JsonElement.class);
        int code = jsonElement.getAsJsonObject().get("code").getAsInt();
        switch (code) {
            case 2:
                System.out.println("Received '获取令牌' response from " + packet.sender().getHostString() + ":" + packet.sender().getPort());
                String token = jsonElement.getAsJsonObject().get("token").getAsString();
                getTokenHandler.saveTokenToRedis(token);
                break;
            case 4:
                System.out.println("Received '作废令牌' response from " + packet.sender().getHostString() + ":" + packet.sender().getPort());
                //待实现，当响应完成后，也应从redis中删除令牌，因为数据存储服务器不再接收该令牌，因此没有存储的必要
                break;
            case 6:
                System.out.println("Received '获取所有气象站编号信息' response from " + packet.sender().getHostString() + ":" + packet.sender().getPort());
                //待实现，这里应该将获取的data作某种字符串处理，得到其中的值，然后存储进station表中
                break;
            case 8:
                System.out.println("Received '获取指定气象站的数据日期范围' response from " + packet.sender().getHostString() + ":" + packet.sender().getPort());
                //待实现，这里应该将获取的data作某种字符串处理，得到其中的值，然后存储进station表中
                break;
            case 10:
                System.out.println("Received '请求气象数据' response from " + packet.sender().getHostString() + ":" + packet.sender().getPort());
                /**
                 * 待实现，这里应该将获取的station、date、data以目前假数据规范，即有序集合形式持久化成rdb文件
                 * 尝试将其恢复至redis，名称应以”气象站编号_weather_年份“为规范
                 * 完成redis-to-mysql，可调用python脚本
                 * 合作实现
                 **/
                break;
            default:
                System.out.println("Received unknown response from " + packet.sender().getHostString() + ":" + packet.sender().getPort());
                break;
        }
    }
}
```

此处展示接收到code为2的响应码时，将令牌存放在redis中的操作：

```Java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

@Component
public class GetTokenHandler {
    private static final String TOKEN_KEY_PREFIX = "token:";
    private static final long EXPIRATION_TIME = 7;
    private static final TimeUnit TIME_UNIT = TimeUnit.DAYS;
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    public void saveTokenToRedis(String token) {
        String key = TOKEN_KEY_PREFIX + token;
        byte[] tokenBytes = token.getBytes(StandardCharsets.UTF_8);
        String tokenStr = new String(tokenBytes, StandardCharsets.UTF_8);

        redisTemplate.execute((RedisCallback<String>) connection -> {
            connection.set(key.getBytes(), tokenStr.getBytes());
            connection.expire(key.getBytes(), TIME_UNIT.toSeconds(EXPIRATION_TIME));
            return null;
        });

        String savedToken = redisTemplate.opsForValue().get(key);
        System.out.println("Token saved to Redis: " + savedToken);
    }
}
```

### 运行程序

该程序一经运行则自动向服务端发送请求，仅为测试用。真实情况应该由数据分析服务根据需求自行调用数据获取程序定义的HTTP端点，进而向服务端发送请求。

```Java
import com.weather.client.UDPClient;
import com.weather.service.udpService.MeteoDataService;
import com.weather.service.udpService.TokenService;
import lombok.AllArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@AllArgsConstructor
public class MeteoObtainApplication implements CommandLineRunner {
    private final UDPClient udpClient;
    private final TokenService tokenService;
    private final MeteoDataService meteoDataService;

    public static void main(String[] args) {
        SpringApplication.run(MeteoObtainApplication.class);
    }

    @Override
    public void run(String... args) throws Exception {
        tokenService.getToken();
        tokenService.voidToken();
        meteoDataService.getAllStationCode();
        meteoDataService.getAllStationDataRange();
        meteoDataService.getMeteoData();
    }
}
```

### 使用网络调试工具进行测试

应首先打开网络调试工具，将其作为服务端；

[![image.png](https://i.postimg.cc/nLjmnFpd/image.png)](https://postimg.cc/5HJy3MHv)

可在数据发送框模拟响应数据。

然后运行数据获取程序，一经运行，便可看见请求：

[![image.png](https://i.postimg.cc/fRZZwBs1/image.png)](https://postimg.cc/RNP2d1NT)

发送数据即可在控制台看到响应：

[![image.png](https://i.postimg.cc/cLDzVmLR/image.png)](https://postimg.cc/4Y9wcpty)