# sign-in-with-apple-id-java-server-validation

**苹果授权登录，服务端校验逻辑。本程序使用java实现**

客户端发起sign in with apple id后得到identityToken和authorizationCode。

identityToken是一个JSON Web Signature(JWS)格式的字符串，这个是客户端拿到的用户信息。

authorizationCode用于校验当前请求的合法性。同时通过team_id、clent_id、authorizationCode等可以从apple服务中获取一个新的identityToken。

对比客户端的identityToken与服务端下发的identityToken，来校验当前请求的合法性。

--------------------------
**sign in with apple id server side validation using java.**

After the client initiates sign in with apple id, can gets the identityToken and authorizationCode.

identityToken is a JSON Web Signature (JWS) format string, which is the user information obtained by the client.

authorizationCode is used to verify the validity of the current request. At the same time, a new identityToken can be obtained by the apple service through team_id, clent_id, authorizationCode, etc.

Compare the identityToken obtained by the client with the identityToken obtained by the server, to verify current request valid or not.

--------------------------
apple doc:
https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api