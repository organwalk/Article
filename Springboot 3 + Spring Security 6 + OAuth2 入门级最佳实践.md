# Springboot 3 + Spring Security 6 + OAuth2 入门级最佳实践

当我的项目基于 SpringBoot 3 而我想使用Spring Security，最终不幸得到WebSecurityConfigurerAdapter被废弃的消息。本文档就是在这样的情况下产生的。

## 开发环境

应该基于：

- SpringBoot 3.x版本
- JDK 17

## 添加依赖

```xml
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
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
</dependency>
```

## 基本启动

在浏览器访问默认8080端口可以得到默认授权页面：

[![image.png](https://i.postimg.cc/XYxY2vFc/image.png)](https://postimg.cc/4Y7GysWm)

用户名为user，密码在控制台中自动生成：

[![image.png](https://i.postimg.cc/LXPRM4qW/image.png)](https://postimg.cc/jwRBHb46)

写一个测试api：

```java
@RestController
@RequestMapping("/api")
public class testController {
    @GetMapping("/hello")
    public ResponseEntity hello(){
        return ResponseEntity.ok("hello,this is my api");
    }
}
```

登录后即可正常访问：

[![image.png](https://i.postimg.cc/xjPhNbSR/image.png)](https://postimg.cc/kDBfkGG6)

也可以退出登录：

[![image.png](https://i.postimg.cc/jjHm6M1D/image.png)](https://postimg.cc/HJL6d9dm)



## Basic Auth授权流程

一个最基础的授权流程图：

[![image.png](https://i.postimg.cc/59qrZQ7z/image.png)](https://postimg.cc/SjRV9RpQ)

新建一个SecurityConfig类：

```java
// 使用@EnableWebSecurity注解开启Spring Security功能
@EnableWebSecurity
public class SecurityConfig {

    // 定义一个SecurityFilterChain bean，用于配置安全过滤器链
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 配置授权请求规则
                .authorizeRequests()
                // 任何请求都需要认证
                .anyRequest()
                .authenticated()
                // 使用and()方法连接多个配置
                .and()
                // 开启HTTP基本认证功能
                .httpBasic();
        return http.build();
    }
}
```

可在API测试工具（此处为ApiFox）得到如下结果：

[![image.png](https://i.postimg.cc/XJbvY1Rx/image.png)](https://postimg.cc/p9sv0CXn)



## JWT身份验证过滤器

[![image.png](https://i.postimg.cc/ZK44vyDY/image.png)](https://postimg.cc/Jt699tLS)

**添加依赖**

```xml
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
```

1. io.jsonwebtoken:jjwt依赖是Java JWT（JSON Web Token）库，它提供了一种方便的方法来生成、解析和验证JWT。在本例中，该依赖项用于生成和解析JWT，并提供了一些常用的JWT功能，如设置JWT的过期时间、签名和验证等。
2. javax.xml.bind:jaxb-api依赖是Java体系结构与XML绑定（Java Architecture for XML Binding，JAXB）API的一部分，它提供了一种将Java对象与XML文档相互转换的方法。在本例中，jjwt库依赖了javax.xml.bind包，因此需要将其添加到项目中以解决可能的编译错误。

**新建一个JwtUtils，帮助我们进行Jwt令牌生成与解析**

```java
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@Component
public class JwtUtils {
    private String jwtSigningKey = "secret";

    /**
     * 从JWT中提取用户名
     */
    public String extractUsername(String token){
        return extractClaim(token,Claims::getSubject);
    }

    /**
     * 从JWT中提取过期时间
     */
    public Date extractExpiration(String token){
        return extractClaim(token,Claims::getExpiration);
    }

    /**
     * 检查JWT是否包含指定的声明
     */
    public boolean hasClaim(String token,String claimName){
        final Claims claims = extractAllClaims(token);
        return claims.get(claimName) !=null;
    }

    /**
     * 从JWT中提取指定声明
     */
    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * 从JWT中提取所有声明
     */
    public Claims extractAllClaims(String token){
        try {
            return Jwts.parser().setSigningKey(jwtSigningKey).parseClaimsJws(token).getBody();
        } catch (Exception e) {
            e.printStackTrace();
            // return a default Claims object or null
        }
        return null;
    }

    /**
     * 检查JWT是否已过期
     */
    public Boolean isTokenExpired(String token){
        Date expirationDate = extractExpiration(token);
        if (expirationDate == null) {
            return true; // or false based on your requirements
        }
        return expirationDate.before(new Date());
    }

    /**
     * 生成JWT
     */
    public String generateToken(UserDetails userDetails){
        Map<String,Object> claims = new HashMap<>();
        return createToken(claims,userDetails);
    }

    /**
     * 生成带有指定声明的JWT
     */
    public String generateToken(UserDetails userDetails,Map<String,Object>claims){
        return createToken(claims,userDetails);
    }

    /**
     * 创建JWT
     */
    public String createToken(Map<String, Object> claims, UserDetails userDetails){
        return Jwts.builder().setClaims(claims)
                .setSubject(userDetails.getUsername())
                .claim("authorities",userDetails.getAuthorities())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(24)))
                .signWith(SignatureAlgorithm.HS256,jwtSigningKey).compact();
    }

    /**
     * 验证JWT是否有效
     */
    public Boolean isTokenValid(String token,UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
```

generateToken()和createToken()是生成JWT的核心方法，它们使用了Jwts.builder()来构建JWT，并设置了一些常用的JWT功能，如设置JWT的过期时间、签名和验证等。isTokenValid()方法用于验证JWT是否有效，它检查JWT的用户名是否与用户详细信息中的用户名匹配，并检查JWT是否已过期。其他方法都是用于辅助功能的方法，用于从JWT中提取相关信息或检查JWT是否包含指定的声明。

**创建Dao，并配合Security一起使用。理论上，此处可以配合MySQL与Redis一起使用，但这并非本文重点**

```java
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Repository
public class UserDao {

    // 在内存中存储应用程序的用户信息，这里只有一个用户
    private final static List<UserDetails> APPLICATION_USERS = Arrays.asList(
            new User(
                    "harukisea0@gmail.com", // 用户名
                    "password", // 密码
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")) // 用户角色
            )
    );

    // 根据用户邮箱查找用户
    public UserDetails findUserByEmail(String email){
        return APPLICATION_USERS
                .stream()
                .filter(u-> u.getUsername().equals(email)) // 使用 Lambda 表达式过滤用户
                .findFirst() // 返回第一个匹配的用户
                .orElseThrow(()->new UsernameNotFoundException("No user was found")); // 如果没有匹配的用户，则抛出异常
    }
}
```

**创建JWT身份认证过滤器**

```java
@Component
@RequiredArgsConstructor
public class JwtAthFilter extends OncePerRequestFilter {

    private final UserDao userDao;
    private final JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 获取 HTTP 请求头部中的 Authorization 字段
        final String authHeader = request.getHeader(AUTHORIZATION);
        final String userEmail;
        final String jwtToken;

        // 如果 Authorization 字段不存在或者不符合 Bearer Token 的格式，则跳过该过滤器
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 提取 JWT Token，并从中获取用户邮箱
        jwtToken = authHeader.substring(7);
        userEmail = jwtUtils.extractUsername(jwtToken);

        // 如果用户邮箱不为空且未进行身份验证
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // 根据用户邮箱从 UserDao 中查找用户
            UserDetails userDetails = userDao.findUserByEmail(userEmail);

            // 如果 JWT Token 有效，则进行身份验证
            if (jwtUtils.isTokenValid(jwtToken, userDetails)) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // 继续处理请求
        filterChain.doFilter(request, response);
    }
}
```

该过滤器用于检查 HTTP 请求头部中是否包含 JWT Token，如果存在则从中提取出用户邮箱并进行身份验证。具体而言，该过滤器首先提取 HTTP 请求头部中的 Authorization 字段，检查其是否符合 Bearer Token 的格式。如果不符合，该过滤器将直接跳过，继续处理请求。如果 Authorization 字段符合 Bearer Token 的格式，则该过滤器将提取 JWT Token，并从中获取用户邮箱。如果用户邮箱不为空且未进行身份验证，则该过滤器将从 UserDao 中查找该用户，并使用 JwtUtils 类的 isTokenValid 方法验证 JWT Token 是否有效。如果 JWT Token 有效，则该过滤器将创建一个 UsernamePasswordAuthenticationToken 对象，并将其添加到 SecurityContextHolder 中，以进行身份验证。最后，该过滤器将继续处理请求。

**配置安全过滤链**

Q：为什么不使用antMatchers？

A：可参考这篇[官方文档](https://docs.spring.io/spring-security/reference/5.8/migration/servlet/config.html)，Security5.8以上版本删除了过往常用的大量写法。

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAthFilter jwtAthFilter;
    private final UserDao userDao;

    // 定义一个 SecurityFilterChain bean，用于配置安全过滤器链
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 配置授权请求规则
                .csrf().disable()
                .authorizeRequests()
            	//认证请求无需授权
                .requestMatchers("/api/auth/**")
                .permitAll()
                // 任何请求都需要授权
                .anyRequest()
                .authenticated()
                // 使用 and() 方法连接多个配置
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // 配置 AuthenticationProvider bean
    @Bean
    public AuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    // 配置 AuthenticationManager bean
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    // 配置密码编码器 bean
    @Bean
    public PasswordEncoder passwordEncoder() {
        //return new BCryptPasswordEncoder();
        return NoOpPasswordEncoder.getInstance();
    }

    // 配置 UserDetailsService bean
    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
                return userDao.findUserByEmail(email);
            }
        };
    }
}
```

**创建一个测试用实体类**

```java
@Getter
@Setter
@NoArgsConstructor
public class AuthenticationRequest {

    private String email;
    private String password;
}
```

**创建一个测试用授权认证控制器**

```java
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationManager authenticationManager;
    private final UserDao userDao;
    private final JwtUtils jwtUtils;

    @PostMapping("/login")
    public ResponseEntity<String> authenticate(
            @RequestBody AuthenticationRequest request
    ){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(),request.getPassword())
        );
        final UserDetails user = userDao.findUserByEmail(request.getEmail());
        if (user != null){
            return ResponseEntity.ok(jwtUtils.generateToken(user));
        }
        return ResponseEntity.status(400).body("Some error has occurred");
    }
}
```

**一例测试**：

[![image.png](https://i.postimg.cc/1zFksd8t/image.png)](https://postimg.cc/3yKSZnC5)

**令牌解析：**

[![image.png](https://i.postimg.cc/7ZksSLhx/image.png)](https://postimg.cc/3dtFTY26)

解析地址：[JSON Web Tokens - jwt.io](https://jwt.io/)

**资源获取测试：**

![image-20230502184052124](C:\Users\haruki\AppData\Roaming\Typora\typora-user-images\image-20230502184052124.png)





## Github作为授权服务器

可以使用第三方服务作为授权服务器。Spring Security 6 内置了Github、Google、FaceBook、OKTA的支持。

您可以选择在[此处](https://github.com/settings/applications/new)获取Github的支持，以注册一个属于您自身的全新OAuth应用程序。

[![image.png](https://i.postimg.cc/sXcy85yT/image.png)](https://postimg.cc/34dP04kG)

**创建一个基于OAuth授权认证的客户端程序**

一如既往，该程序基于Springboot 3.x版本。

需要在此基础上添加由Springboot管理的如下核心依赖：

```xml
<dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
<dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

在您的配置文件进行如下基本配置：

```yml
server:
  port: 8080
spring:
  security:
    oauth2:
      client:
        registration:
          github:
            clientId: 515419724890eea8f1be
            clientSecret: ***************7128f77d
```

您应该将客户端ID及其密钥替换为您自身在Github上创建OAuth应用程序所获取的。

然后，我们可以创建并配置一个基本的安全过滤链：

```
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf()
                .disable()
                .authorizeHttpRequests()
                .anyRequest()
                .authenticated()
                .and()
                .oauth2Login()
        ;
        return http.build();
    }
}
```

作为开发环境的测试，这个安全过滤链实现了CSRF攻击防护的禁用、对应用程序的每一个URL进行身份验证，启用OAuth2登录。

可以考虑写一个测试用http端点：

```java
@GetMapping("/hello")
    public String loginResult(){
        return "hello,this is my api";
    }
```

启动该客户端程序，您将会得到如下授权界面：

[![image.png](https://i.postimg.cc/7Pzs9qHW/image.png)](https://postimg.cc/RqMLV5n7)

授权登录后请求我们刚刚编写的http端点，可以在浏览器得到：

```
hello,this is my api
```

通常，您可以考虑在Github中删除授权token。



## 自定义授权服务器

您也可以使用您所创建的授权服务器来处理您所创建的客户端进行授权认证。

首先，创建一个auth-service模块，该模块基于Springboot 3.x版本，用于创建授权服务器

您应该在此基础之上添加核心依赖：

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
</dependencies>
```

编写授权服务器的安全过滤链：

```java
import static org.springframework.security.config.Customizer.withDefaults;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@SuppressWarnings("deprecation")//忽略过时警告
@Configuration
public class SecurityConfig {

    @Bean
    @Order(1)//指定执行优先级
    public SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        return http
                //为 OAuth2 认证服务器添加 OIDC 支持
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(withDefaults())
                .and()
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                        //当未经身份验证的用户尝试访问受保护的资源时，将用户重定向到Security的默认登录页面
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                //配置 OAuth2 资源服务器以使用 JWT 令牌进行身份验证
                .build();

    }

    @Bean
    @Order(2)
    //表单登录与身份验证的请求授权
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .formLogin(withDefaults())
                //授权任何已认证的用户可以访问任何请求
                .authorizeHttpRequests(authorize ->authorize.anyRequest().authenticated())
                .build();

    }

    //该 Bean 提供了一个存储在内存中的用户
    @Bean
    public UserDetailsService userDetailsService() {
        var user1 = User.withUsername("user")
                .password("password")
                .authorities("read")
                .build();
        return new InMemoryUserDetailsManager(user1);
    }

    //以纯文本形式保存密码，实际开发应该实现 BCryptPasswordEncoder()
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    /*
        向OAuth2认证服务器注册一个客户端应用程序进行授权
        该 Bean 提供了一个内存中的注册客户端存储，用于 OAuth2 认证服务器的客户端授权
        客户端应使用此处设置的值作为配置项
    */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        //生成随机UUID作为客户端唯一标识，避免多个客户端时ID冲突
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client") //设置授权客户端ID
                .clientSecret("secret") //设置客户端密钥
                .scope(OidcScopes.OPENID)   //设置客户端的范围，这里使用了 OpenID Connect 的标准范围
                /*
                    设置客户端的重定向 URI，当用户授权后，OAuth2 认证服务器将重定向到该 URI
                    由于OAuth2认证服务器的安全性设置，此处必须使用127.0.0.1
                    使用localhost会导致拒绝重定向
                 */
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/myoauth2")
                //设置客户端的身份验证方法，这里使用了基本身份验证方法
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                //设置客户端的授权类型，这里使用了授权码授权类型
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    //该Bean用于配置OAuth2认证服务器，该例中我们无需配置
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    //解码Jwt令牌
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    //提供Jwt令牌
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    //固定写法，生成RSA密钥对
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
}
```

在配置文件中可以指定9090端口便于测试：

```
server:
  port: 9090
```

然后，创建client-service模块，用于创建我们的客户端。

同样，它基于 Springboot 3.x 版本，在此基础上，我们还需添加核心依赖：

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-client</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
</dependencies>
```

配置安全过滤链：

```java
import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                //所有请求都需经过授权认证
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated())
                //配置登录URL
                .oauth2Login(oauth2Login ->
                        oauth2Login.loginPage("/oauth2/authorization/myoauth2"))
                //使用默认客户端配置
                .oauth2Client(withDefaults());
        return http.build();
    }
}
```

可以创建一个控制器，写一个http端点用于测试：

```java
@GetMapping("/")
    public String welcome() {

        return "<h1>Welcome!</h1>";
    }
```

在配置文件中编写配置项：

```yml
server:
  port: 8080
spring:
  security:
    oauth2:
      client:
        registration:
          myoauth2:
            provider: spring
            client-id: client
            client-secret: secret
            scope:
              - openid
            authorization-grant-type: authorization_code
            redirect-uri: http://127.0.0.1:8080/login/oauth2/code/myoauth2
        provider:
          spring:
            issuer-uri: http://localhost:9090
```

运行授权服务器，然后运行客户端。

尝试在浏览器地址栏输入http://localhost:8080

[![image.png](https://i.postimg.cc/Bb6SF3VS/image.png)](https://postimg.cc/62kxskKg)

尝试登录：

[![image.png](https://i.postimg.cc/h496LNBg/image.png)](https://postimg.cc/Th3tG71H)

## Authorization Server - Resource Server and OAuth2 Client

现在，我们可以尝试将资源服务纳入授权管理。

**创建Authorization Server**

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
</dependencies>
```

配置安全过滤链：

```java
import static org.springframework.security.config.Customizer.withDefaults;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@SuppressWarnings("deprecation")
@Configuration
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        return http
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(withDefaults())
                .and()
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .build();

    }

    @Bean
    @Order(2)
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .formLogin(withDefaults())
                .authorizeHttpRequests(authorize ->authorize.anyRequest().authenticated())
                .build();

    }

    @Bean
    public UserDetailsService userDetailsService() {
        var user1 = User.withUsername("user")
                .password("password")
                .authorities("read")
                .build();
        return new InMemoryUserDetailsManager(user1);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client")
                .clientSecret("secret")
                .scope("read")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/myoauth2")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

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
}
```

编写配置文件：

```
server:
  port: 9090
```

**创建Resource Server**

```xml
<dependencies>
    <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
  	</dependency>
</dependencies>
```

编写配置文件：

```yml
server:
  port: 8090

spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:9090
```

编写安全过滤链：

```java
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    //从配置文件中获取OAuth2 Jwt令牌签发者的uri
    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    String issuerUri;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.decoder(JwtDecoders.fromIssuerLocation(issuerUri))))
                .build();
    }
}
```

可以写一个测试用http端点，表示该资源服务的资源：

```java
@GetMapping("/")
public String home() {
    LocalDateTime time = LocalDateTime.now();
    return "Welcome Resource Server! - " + time;
}
```

**创建OAuth2 Client**

引入核心依赖：

```xml
<dependencies>
    <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-client</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-webflux</artifactId>
        </dependency>
</dependencies>
```

此处引入了 SpringBoot 3 的新特性，替换了常用的OpenFeign调用其它服务的方式，转而使用Spring自身的声明式HTTP接口。webflux可以让你在调用其它服务时像写控制器一样轻松。

编写配置文件：

```yml
server:
  port: 8080
spring:
  security:
    oauth2:
      client:
        registration:
          myoauth2:
            provider: spring
            client-id: client
            client-secret: secret
            scope:
              - openid
            authorization-grant-type: authorization_code
            redirect-uri: http://127.0.0.1:8080/login/oauth2/code/myoauth2
        provider:
          spring:
            issuer-uri: http://localhost:9090
```

编写安全过滤链：

```java
import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                //所有请求都需经过授权认证
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated())
                //配置登录URL
                .oauth2Login(oauth2Login ->
                        oauth2Login.loginPage("/oauth2/authorization/myoauth2"))
                //使用默认客户端配置
                .oauth2Client(withDefaults());
        return http.build();
    }
}
```

编写一个Client类，用以调用资源服务的资源：

```java
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;


@HttpExchange("http://localhost:8090")
public interface WelcomeClient {

    @GetExchange("/")
    String getWelcome();


}
```

编写该Client的配置类，配置使用 OAuth2 认证的 WebClient，并将其转换为代理对象，以便于进行远程调用。通过 `OAuth2AuthorizedClientManager` 接口管理 OAuth2 授权客户端的生命周期，确保 WebClient 的安全性和可靠性：

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.support.WebClientAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

@Configuration
public class WebClientConfig {

    /**
     * 创建名为 welcomeClient 的 bean，类型为 WelcomeClient。
     * 使用 OAuth2AuthorizedClientManager 作为参数创建 HttpServiceProxyFactory，然后使用它创建客户端。
     *
     * @param authorizedClientManager 用于创建 HttpServiceProxyFactory 的 OAuth2AuthorizedClientManager 实例
     * @return WelcomeClient 实例
     * @throws Exception 如果创建客户端时发生错误，则抛出异常
     */
    @Bean
    public WelcomeClient welcomeClient(OAuth2AuthorizedClientManager authorizedClientManager) throws Exception {
        return httpServiceProxyFactory(authorizedClientManager).createClient(WelcomeClient.class);
    }

    /**
     * 创建 HttpServiceProxyFactory，以便在创建客户端时使用。
     *
     * @param authorizedClientManager 用于创建 HttpServiceProxyFactory 的 OAuth2AuthorizedClientManager 实例
     * @return 创建的 HttpServiceProxyFactory 实例
     */
    private HttpServiceProxyFactory httpServiceProxyFactory(OAuth2AuthorizedClientManager authorizedClientManager) {
        // 创建 ServletOAuth2AuthorizedClientExchangeFilterFunction，使用它来处理 OAuth2 认证
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
                new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);

        // 设置默认的 OAuth2 授权客户端
        oauth2Client.setDefaultOAuth2AuthorizedClient(true);

        // 创建 WebClient，应用 OAuth2 认证配置
        WebClient webClient = WebClient.builder()
                .apply(oauth2Client.oauth2Configuration())
                .build();

        // 创建 WebClientAdapter，它允许我们在创建客户端时使用 WebClient
        WebClientAdapter client = WebClientAdapter.forClient(webClient);

        // 创建 HttpServiceProxyFactory，它可用于创建客户端
        return HttpServiceProxyFactory.builder(client).build();
    }

    /**
     * 创建 OAuth2AuthorizedClientManager 的 bean。
     *
     * @param clientRegistrationRepository 用于管理客户端注册信息的 ClientRegistrationRepository 实例
     * @param authorizedClientRepository   用于管理授权客户端信息的 OAuth2AuthorizedClientRepository 实例
     * @return OAuth2AuthorizedClientManager 实例
     */
    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {

        // 创建 OAuth2AuthorizedClientProvider，用于获取授权客户端
        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .authorizationCode()
                        .refreshToken()
                        .build();

        // 创建 DefaultOAuth2AuthorizedClientManager，使用它来管理授权客户端
        DefaultOAuth2AuthorizedClientManager authorizedClientManager =
                new DefaultOAuth2AuthorizedClientManager(
                        clientRegistrationRepository, authorizedClientRepository);

        // 设置授权客户端提供程序
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        // 返回 OAuth2AuthorizedClientManager
        return authorizedClientManager;
    }

}
```

写一个测试用http端点：

```java
@GetMapping("/")
public String welcome() {

    String welcome = welcomeClient.getWelcome();
    return "<h1>" +  welcome + "</h1>";
}
```

然后运行授权服务、资源服务和客户端

如果你尝试访问资源服务，即 http://localhost:8090 ,会得到：

```
当前无法使用此页面
如果问题仍然存在，请联系网站所有者。
HTTP ERROR 401
```

这是因为资源服务的调用应通过客户端进行，而客户端获取资源服务，则需通过OAuth2认证授权。

接着，我们尝试访问客户端：

[![image.png](https://i.postimg.cc/wv3cDg00/image.png)](https://postimg.cc/DJkXTkVX)

这将自动跳转至默认的授权页面，我们可以在这里进行登录，即可跳转至8080端口，通过客户端获取到资源服务：

```
Welcome Resource Server! - 2023-05-03T14:29:20.723645200
```

## 实现 BCryptPasswordEncoder密码加密

密码加密是一个常见应用。以刚刚创建的授权服务为例，一般来说，您可以在其基础上修改与增加如下代码：

```java
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return NoOpPasswordEncoder.getInstance();
//    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
```

```java
@Bean
public UserDetailsService userDetailsService() {
    var user1 = User.withUsername("user")
            .password(passwordEncoder().encode("password"))//修改此处
            .authorities("read")
            .build();
    return new InMemoryUserDetailsManager(user1);
}
```

```java
@Bean
public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("client")
            .clientSecret(passwordEncoder().encode("secret"))//修改此处
            .scope("read")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .redirectUri("http://127.0.0.1:8080/login/oauth2/code/myoauth2")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .build();

    return new InMemoryRegisteredClientRepository(registeredClient);
}
```

## 在数据库中自定义用户信息

您可以采用 JPA/Hibernate等一切你所熟悉的数据库框架，但这并不是本文档的重点。这里仅以MySQL 8.x与MybatisPlus为例：

延续上面写好的Demo，向您的授权服务添加如下依赖：

```
<dependency>
    <groupId>com.baomidou</groupId>
    <artifactId>mybatis-plus-boot-starter</artifactId>
</dependency>
<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>druid-spring-boot-starter</artifactId>
</dependency>
```

当然，我们需要在配置文件中配置数据库，如果您愿意观察授权服务运行情况，可以像我一样打开监控日志：

```yml
server:
  port: 9090
spring:
  datasource:
    type: com.alibaba.druid.pool.DruidDataSource
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/database?useSSL=false
    username: root
    password: 123456
  mybatis-plus:
    configuration:
      log-impl: org.apache.ibatis.logging.stdout.StdOutImpl
logging:
  level:
    org:
      springframework:
        security: TRACE
```

提供如下由Navicat导出的三个SQL文件供您建表参考：

```sql
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for user
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  `password` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of user
-- ----------------------------
INSERT INTO `user` VALUES (1, 'root', '$2a$12$.b6oalHafQC/beQaqXnwdeLY7M5KxL..is7kEguwQbHX3FPXfgRKW');

SET FOREIGN_KEY_CHECKS = 1;
```

<p align=center>user.sql</p>

我们这里没有实现注册模块，但又想体验密码加密功能，因此推荐从[此处](https://bcrypt-generator.com/)由纯文本密码转换成加密密码存储至数据库中。此处定义的用户信息为：

| 字段     | 值     |
| :------- | :----- |
| name     | root   |
| password | 123456 |

```sql
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for authority
-- ----------------------------
DROP TABLE IF EXISTS `authority`;
CREATE TABLE `authority`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `authority` varchar(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of authority
-- ----------------------------
INSERT INTO `authority` VALUES (1, 'ROLE_USER');
INSERT INTO `authority` VALUES (2, 'ROLE_ADMIN');
INSERT INTO `authority` VALUES (3, 'ROLE_DEVELOPER');

SET FOREIGN_KEY_CHECKS = 1;
```

<p align=center>authority.sql</p>

```sql
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for user_authority
-- ----------------------------
DROP TABLE IF EXISTS `user_authority`;
CREATE TABLE `user_authority`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `authority_id` int NOT NULL,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE = utf8_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of user_authority
-- ----------------------------
INSERT INTO `user_authority` VALUES (1, 1, 1);

SET FOREIGN_KEY_CHECKS = 1;
```

<p align=center>user_authority.sql</p>

**编写授权服务**

我们将注释安全过滤链中的以下代码，因为我们不再需要在内存中创建用户：

```java
//    @Bean
//    public UserDetailsService userDetailsService() {
//        var user1 = User.withUsername("user")
//                .password(passwordEncoder().encode("password"))
//                .authorities("read")
//                .build();
//        return new InMemoryUserDetailsManager(user1);
//    }
```

创建两个实体类其一：User

```java
import lombok.AllArgsConstructor; // 导入 Lombok 库中的注解
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data // 自动生成 getter 和 setter 方法
@NoArgsConstructor // 自动生成无参构造函数
@AllArgsConstructor // 自动生成所有参数的构造函数
@Builder // 自动生成 Builder 类
public class User {
    private Integer id; // 用户 ID
    private String name; // 用户名
    private String password; // 密码

    // 使用 @Builder.Default 指定默认值
    @Builder.Default
    private Boolean accountNonExpired = true; // 账号是否未过期，默认为 true
    @Builder.Default
    private Boolean accountNonLocked = true; // 账号是否未锁定，默认为 true
    @Builder.Default
    private Boolean credentialsNonExpired = true; // 凭证是否未过期，默认为 true
    @Builder.Default
    private Boolean enabled = true; // 账号是否可用，默认为 true
}
```

创建两个实体类其二：Authority

```java
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Authority {

    private Integer id;
    @NonNull
    private String authority;
}
```

创建两个Mapper接口其一：UserMapper

```java
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.weather.entity.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper extends BaseMapper<User> {

}
```

创建两个Mapper接口其二：AuthorityMapper

```java
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.weather.entity.Authority;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface AuthorityMapper extends BaseMapper<Authority> {
}
```

现在，我们应该定义一个表示用户信息的类，并实现了 UserDetails 接口中的方法，以便于在 Spring Security 框架中对用户进行认证和授权：

```java
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import com.weather.entity.Authority;
import com.weather.entity.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.RequiredArgsConstructor;

@Data // 自动生成 getter、setter、equals、hashCode 等方法
@RequiredArgsConstructor // 为 final 属性生成带参构造函数
public class MyUserDetails implements UserDetails {

    private static final long serialVersionUID = 1L;

    private final User user; // 用户信息
    private final List<Authority> authority; // 用户权限列表

    // 实现 UserDetails 接口中的方法
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authority.stream() // 将权限列表转换为流
                .map(auth -> new SimpleGrantedAuthority(auth.getAuthority())) // 将 Authority 对象转换为 GrantedAuthority 对象
                .collect(Collectors.toSet()); // 将转换后的对象集合转换为 Set 类型并返回
    }

    @Override
    public String getPassword() {
        return user.getPassword(); 
    }

    @Override
    public String getUsername() {
        return user.getName(); 
    }

    @Override
    public boolean isAccountNonExpired() {
        return user.getAccountNonExpired(); 
    }

    @Override
    public boolean isAccountNonLocked() {
        return user.getAccountNonLocked(); 
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return user.getCredentialsNonExpired(); 
    }

    @Override
    public boolean isEnabled() {
        return user.getEnabled(); 
    }

}
```

现在我们需要创建一个用户信息存储库类，以存储来自数据库的用户信息。首先实现一个UserRepository接口：

```java
import com.weather.entity.Authority;
import com.weather.entity.User;

import java.util.List;


public interface UserRepository {
    User getUserByName(String name);
    List<Authority> getAuthoritiesByUserId(int userID);
}
```

接下来，您需要写一个该存储库的实现类：

```java
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.weather.entity.Authority;
import com.weather.entity.User;
import com.weather.mapper.AuthorityMapper;
import com.weather.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserRepositoryImpl implements UserRepository {
    private final UserMapper userMapper;
    private final AuthorityMapper authorityMapper;


    @Override
    public User getUserByName(String name) {
        return userMapper.selectOne(new QueryWrapper<User>()
                .eq("name",name)
                .select("id","name","password"));
    }

    @Override
    public List<Authority> getAuthoritiesByUserId(int userID) {
        return authorityMapper.selectList(new QueryWrapper<Authority>()
                .inSql("id","select authority_id from user_authority where user_id = " + userID)
                .select("id","authority"));
    }

}

```

最终，我们需要将数据库中获取的用户信息传入UserDetails：

```java
import com.weather.entity.Authority;
import com.weather.entity.User;
import com.weather.model.MyUserDetails;
import com.weather.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

import java.util.List;
import java.util.Optional;


@Service
@RequiredArgsConstructor
public class MyUserDetailService implements UserDetailsService {
    private final UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.getUserByName(username);
        List<Authority> authorities = userRepository.getAuthoritiesByUserId(user.getId());
        return Optional.ofNullable(user)
                .map(u -> new MyUserDetails(u, authorities))
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
```

现在，我们就可以使用数据库所定义的用户进行登录。

## 自定义OAuth2令牌：

在授权服务的安全过滤链上增加如下代码：

```java
@Bean
OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
    return context -> {
        Authentication principal = context.getPrincipal();
        if (context.getTokenType().getValue().equals("id_token")) {
            context.getClaims().claim("Test", "Test Id Token");
        }
        if (context.getTokenType().getValue().equals("access_token")) {
            context.getClaims().claim("Test", "Test Access Token");
            Set<String> authorities = principal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
            context.getClaims().claim("authorities", authorities)
                    .claim("user", principal.getName());
        }

    };
}
```

## Jwt令牌身份验证转换器

我们现在可以考虑实现将JWT令牌转换为身份验证对象，以便在Spring Security中进行身份验证和授权。

首先，我们在资源服务器的安全过滤链中编写如下代码，返回一个身份验证转换对象：

```
@Bean
JwtAuthenticationConverter jwtAuthenticationConverter() {
	//用于从JWT令牌中提取授权信息并将其转换为GrantedAuthority对象的集合
    JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    //JWT令牌中的授权信息在名为"authorities"的声明中
    grantedAuthoritiesConverter.setAuthoritiesClaimName("authorities");
    //授权信息中不包含前缀
    grantedAuthoritiesConverter.setAuthorityPrefix("");

    JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
    jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
    return jwtAuthenticationConverter;
}
```

这将使Jwt令牌中的身份写入Authentication对象中，进而可供调用。

写一个测试用http端点：

```java
@GetMapping("/")
    public String home(Authentication authentication) {
        LocalDateTime time = LocalDateTime.now();
        return "Welcome ResourceServer! - " + time + "<br>" + authentication.getName() + " - " + authentication.getAuthorities();
    }
```

身份验证通过后，您将得到如下结果：

```
Welcome ResourceServer! - 2023-05-03T19:47:27.225993700
root - [ROLE_USER]
```

## 实现客户端登录后获取权限信息

在客户端的安全过滤链中编写以下代码：

```Java
private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        final OidcUserService delegate = new OidcUserService();

        return (userRequest) -> {
            OidcUser oidcUser = delegate.loadUser(userRequest);
            OAuth2AccessToken accessToken = userRequest.getAccessToken();
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
            try {
                JWT jwt = JWTParser.parse(accessToken.getTokenValue());
                JWTClaimsSet claimSet = jwt.getJWTClaimsSet();
                Collection<String> userAuthorities = claimSet.getStringListClaim("authorities");
                mappedAuthorities.addAll(userAuthorities.stream()
                        .map(SimpleGrantedAuthority::new)
                        .toList());
            } catch (ParseException e) {
                System.err.println("Error OAuth2UserService: " + e.getMessage());
            }
            oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
            return oidcUser;
        };
    }
```

该方法首先使用 `delegate` 对象（即 `OidcUserService`）来加载用户信息。然后从 `userRequest` 对象中获取到 `OAuth2AccessToken` 并解析出其中的 JWT，从中提取出用户的权限信息。最后，将用户信息和权限信息封装成一个新的 `OidcUser` 对象，用于后续的认证和授权。

`OidcUser`是Spring Security框架中的一个接口，用于表示OpenID Connect（OIDC）认证成功后的用户信息。在OAuth 2.0和OIDC授权流程中，用户通过认证服务器进行身份验证，并在认证成功后，认证服务器会返回一个包含用户信息的JWT令牌。`OidcUser`接口用于表示这个JWT令牌中包含的用户信息。

这里同样会将用户信息存入Authentication对象中。因为用户信息是在 `oauth2UserService()` 方法中被处理的，最终会被封装成一个 `OidcUser` 对象。`OidcUser` 实现了 Spring Security 的 `Authentication` 接口，因此可以将其作为认证信息存储在 `SecurityContext` 中，用于后续的授权访问。

```java
@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http,ClientRegistrationRepository clientRegistrationRepository) throws Exception {

    String base_uri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
    DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, base_uri);
    resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());

    http
            //所有请求都需经过授权认证
            .authorizeHttpRequests(authorize -> authorize
                    .anyRequest().authenticated())
            //配置登录URL
            .oauth2Login(oauth2Login ->{
                        oauth2Login.loginPage("/oauth2/authorization/myoauth2");
                        oauth2Login.authorizationEndpoint().authorizationRequestResolver(resolver);
                        oauth2Login.userInfoEndpoint(userInfo -> userInfo
                        .oidcUserService(this.oidcUserService()));
                    })

            //使用默认客户端配置
            .oauth2Client(withDefaults());
    return http.build();
}
```

这个方法接收一个`HttpSecurity`对象，用于定义HTTP请求的安全配置，以及一个`ClientRegistrationRepository`对象，用于存储第三方认证服务的客户端配置。

这个方法主要完成以下配置：

- 对所有请求进行授权认证，要求用户登录。
- 设置OAuth 2.0登录的URL。
- 配置OAuth 2.0的授权端点，使用客户端的PKCE（Proof Key for Code Exchange）来增加安全性。
- 设置OIDC（OpenID Connect）用户服务，用于获取用户权限信息。
- 使用默认的OAuth 2.0客户端配置。

写一个测试用http端点：

```java
@GetMapping("/")
public String welcome(Authentication authentication) {
    String authorities = authentication.getName() + " - " + authentication.getAuthorities().toString();
    String welcome = welcomeClient.getWelcome();
    return "<h1>" +  welcome + "</h1><h2>" + authorities + "</h2>";
}
```

授权认证成功后，将得到如下内容：

```
Welcome ResourceServer! - 2023-05-03T19:59:44.575374
root - [ROLE_USER]
root - [ROLE_USER]
```

## 获取刷新令牌

一般来说，用户登录后会得到一个令牌，这个令牌在某种情况下过期或销毁后，用户需要重新登录以获取令牌。而刷新令牌的设计弥补了这一点。您可以通过刷新令牌，在旧令牌过期或销毁后获得新的令牌，以维持您的登录状态，并保持安全性，而无需重新登录获取令牌。这在手机A应用（您会发现大多数手机应用在登录一次后会始终保持着登录状态）非常常见。一些第三方授权服务也会使用刷新令牌以延长用户访问令牌的有效期。

**编写客户端的控制器**

可以在控制器中编写下列代码：

```java
	private final WelcomeClient welcomeClient;
	private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;
	
	@GetMapping("/")
	public String welcome(Authentication authentication) {
		
		String authorities = authentication.getName() + " - " + authentication.getAuthorities().toString();
		String welcome = welcomeClient.getWelcome();			
		return "<h1>" +  welcome + "</h1><h2>" + authorities + "</h2>";
	}
	
	@GetMapping("/token")
	public String token(Authentication authentication) {
		
		//Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		
		OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
		OAuth2AuthorizedClient oAuth2AuthorizedClient = oAuth2AuthorizedClientService
				.loadAuthorizedClient(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId(), oAuth2AuthenticationToken.getName());
		String jwtAccessToken = oAuth2AuthorizedClient.getAccessToken().getTokenValue();
		String jwtRefrechToken = oAuth2AuthorizedClient.getRefreshToken().getTokenValue();
		return "<b>JWT Access Token: </b>" + jwtAccessToken + "<br/><br/><b>JWT Refresh Token:  </b>" + jwtRefrechToken;
	}
	
	@GetMapping("idtoken")
	public String idtoken(@AuthenticationPrincipal OidcUser oidcUser) {
		OidcIdToken oidcIdToken = oidcUser.getIdToken();
		String idTokenValue = oidcIdToken.getTokenValue();
		return "<b>Id Token: </b>" + idTokenValue;
	}
```



## **参考：**

[配置迁移 :Spring 安全性](https://docs.spring.io/spring-security/reference/5.8/migration/servlet/config.html)

[Spring Security Tutorial - [NEW] [2023]](https://www.youtube.com/watch?v=b9O9NI-RJ3o)

[OAuth2 & Spring boot 3 & Social login | never been easier](https://www.youtube.com/watch?v=2WNjmT2z7c4&t=12s)

[Spring Boot 3 Tutorial Security - Oauth2 - Authorization Server - Resource Server and OAuth2 Client](https://www.youtube.com/watch?v=bl1VGCasGXk)

[Configure OAuth2 Spring Authorization Server with JWT support | Sergey Kryvets Blog (skryvets.com)](https://skryvets.com/blog/2020/04/04/configure-oauth2-spring-authorization-server-with-jwt-support/)