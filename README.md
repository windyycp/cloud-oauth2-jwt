# cloud-oauth2-jwt

springboot3.2 + oauth2-authorization-server1.2.7 + jwt + mybaitsplus3.5.10 + mysql8

# 项目介绍

基于spring-boot-starter-oauth2-authorization-server官网示例， 使用mysql8存储oauth2的相关信息

# 模块介绍

auth-common 通用模块，包括基础仓库信息、mybatis-plus配置信息、基础工具类等  
auth-server oauth2的授权服务器  
auth-resource oauth2的资源服务器

# 使用说明

1. 创建数据库simple，并导入script/simple.sql文件
2. 修改auth-server和auth-resource配置文件中的mysql和redis配置
3. 运行auth-server，启动 http://127.0.0.1:8080
4. 运行auth-resource，启动 http://127.0.0.1:8081

# 认证流程

1. 访问
   http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id=my-client&scope=openid&redirect_uri=http://127.0.0.1:8080/test/code
2. 输入用户名和密码（test 123456），点击登录，会自动跳转到http://127.0.0.1:8080/test/code， 该接口已实现token获取，并输出access_token到控制台
3. 使用第2步的token, header使用 Authorization Bearer {token} 访问 http://127.0.0.1:8081/user/info 获取用户信息
