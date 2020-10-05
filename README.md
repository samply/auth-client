# Samply.Auth.Client

The Samply.Auth Client library offers a client, that uses the REST interface
of the Samply.Auth application. It offers methods for all Samply.Auth workflows:

- Your application is a registered client in the Samply.Auth service
- Your application is *not* a registered client in the Samply.Auth service
- Your application already has an access token whose validity is nearing its end

An access token is valid for several hours. After this period of time, the
access token is no longer valid and should be exchanged for a new access token,
if necessary. You can use the refresh token that you got earlier to get a new
access token. This approach will only work if you used the first approach
earlier.

## Build

Use maven to build the jar:

```
mvn clean package
```

Use it as a dependency:

```xml
<dependency>
    <groupId>de.samply</groupId>
    <artifactId>auth-client</artifactId>
    <version>VERSION</version>
</dependency>
```

# Getting started

`Samply.Auth` implements parts of [OpenID-Connect](http://openid.net/specs/openid-connect-core-1_0.html), which is based on OAuth2. OpenID-Connect is a web based authentication model,
that uses simple HTTP requests and browser redirection for authentication. Samply.Auth also extends OpenID-Connect for authorization.

This "Getting Started" guide will show you the necessary steps required to authenticate users of your web-based application with Samply.Auth.

## Terminology

1. Identity Provider: The application that stores the credentials (e.g. username and password) and user informations such as his name.
2. Client: An application that wants to use the identity provider.
3. User-Client: An application that acts on behalf of one (!) user only, e.g. a registry. It authenticates itself with a public key.
4. Token: A signed JWT (JSON Web Token, signed by the identity provider) that stores informations. It should not be known to the browser.
5. Code: A random short living string, that has been issued for a specific client for get a new access token.
6. Scope: A string that identifies a permission of an access token, e.g. the scope "mdr" grants access to the REST interface of the MDR


This exemplary workflow shows how your application (the client) can use Samply.Auth (the Identity Provider) to authenticate users.

## Workflow

1. Register your client at Samply.Auth. This step is necessary only once and can be performed by the Samply.Auth administrator only.
  He needs at least one root URL of your application, e.g. `https://my.awesome.application.org/`.
2. You will get the following attributes in return:
    - Your client ID (public, in this example it is abc)
    - Your client secret (private, in this example it is ghz)
    - The public key that must be used to verify the tokens
    - The target URL, see below
3. Instead of storing user credentials in your database, let Samply.Auth handle those (and various external identity providers supported by Samply.Auth).
  You need a mapping of Samply.Auth users and your users, each Samply.Auth user is identifiable by a string, e.g. `https://samply.auth.de/users/23`.
  This so called subject is unique.
4. (optional) Generate a random string, called the state, for each session. This state is important against Cross-Site-Request-Forgery attacks.

On your webpage create a link with the target you got from the Samply.Auth administrator:

```
https://auth.samply.de/grant.xhtml?scope=openid&client_id=abc&redirect_uri=https%3A%2F%2Fmy.awesome.application.org%2Flogin.xhtml&state=your_state
```

Keep in mind to encode the redirect URL properly.

Samply.Auth will then ask the user to login using his credentials or redirect him to another identity provider.
The exact way of authentication is transparent to the client: The user might authenticate via password, via another OAuth2 mechanism, via Shibboleth, it does *not* matter to your application.
In the end of this process Samply.Auth will generate a random string (the code) and redirect the user back to the URL you provided
in the link above via the `redirect_uri` parameter. This URL must be known to Samply.Auth as redirect URL (the URL from the registration process),
otherwise Samply.Auth will reject the request. So the user is redirected back to your page with the additional parameter `code`, in this example back to

```
https://my.awesome.application.org/login.xhtml?code=234fdwe
```

In your application you must now use this code to get a new access token. This must be done via the REST interface of Samply.Auth by calling:

```
POST https://auth.samply.de/oauth2/token

{
    "code":"234fdwe",
    "client_id":"abc",
    "client_secret":"ghz"
}
```

Response:

```
{
     "access_token":"THE_ACCESS_TOKEN",
     "id_token":"ID_TOKEN",
     "refresh_token":"REFRESH_TOKEN"
}
```

In exchange you will get three tokens: the access token, the ID token and the refresh token. Each token is encoded as JWT and
serves a certain purpose:

- Use the access token to access resources on other servers, if necessary
- Use the ID token to get personal informations about the user, e.g. his real name or email address
- Use the refresh token to get a new access token, if the old access token expired

Even though you have retrieved the tokens via https, the OpenID specification requires you to
validate the tokens:

1. Validate the signature using the public key that the Samply.Auth administrator gave you earlier
2. Check the timestamps of the tokens, so that `nbf` < now < `exp` is true.
3. Check the type for each token
4. Check the audience, if applicable (ID token): it must match your client ID
5. Check the state: it must match the state you generated earlier


After those steps the user is authenticated in your application.


Each token has its own set of attributes.

```
access token

{
  "exp": 1460992953,                        ### not after (Timestamp)
  "nbf": 1460984853,                        ### not before (Timestamp)
  "iat": 1460985753,                        ### Issued at (Timestamp)
  "sub": "https://auth.samply.de/users/23", ### Subject ID (User ID)
  "scope": [
    "openid"                                ### Scopes in this access token
  ],
  "permissions": {},                        ### Permissions granted to the user
  "iss": "https://auth.samply.de",          ### Issuer
  "state": "flhdq58di9dbi",                 ### State, that has been send with the initial request
  "jti": "0bf772c5-3184-488f-8d34-ebf029f6e8b9",  ### JWT ID
  "type": "ACCESS_TOKEN"                    ### Type of this token
}



ID token

{
  "sub": "https://auth.samply.de/users/23", ### see access token
  "iss": "https://auth.samply.de",          ### see access token
  "iat": 1460985753,                        ### see access token
  "nbf": 1460984853,                        ### see access token
  "exp": 1460992953,                        ### see access token
  "usertype": "NORMAL",                     ### User type, disregard for most cases
  "type": "ID_TOKEN",                       ### see access token
  "lang": "en",                             ### users preferred language
  "locations": [],                          ### locations, that this user belongs to
  "email": "myself@testshib.org",           ### users email address
  "externalLabel": "TestShib",              ### label of the external identity provider
  "description": [],                        ### description, if available (only with public key authentication)
  "roles": [],                              ### users roles
  "name": "Me Myself And I",                ### users real name
  "permissions": {},                        ### users permissions
  "aud": "local-mdr",                       ### target audience for this ID token. Disregard, if audience is not your client-id
  "jti": "34c46501-e1ae-4105-8457-d6e73f0c38b1" ### JWT-ID
}
```

The attributes of the refresh token are not important and can be ignored.


## Using Samply.Auth.Client

If you use Java and are familiar with Maven, you can use our [Samply.Auth.Client](../usage.html) library, that
will ease the integration of Samply.Auth in your application.

# Library usage

## Maven

If you use Maven, you can just add the library dependency:

```
<dependency>
    <groupId>de.samply</groupId>
    <artifactId>auth-client</artifactId>
    <version>VERSION</version>
</dependency>
```

Replace `VERSION` with the library version you want to use.

## Workflows

There are three different ways to get an access token from the central Identity
Provider (IdP). This guide shows how you can use them.

### Your application is a registered client in the IdP

In this workflow you have the following values at hand:

- your client ID, a random string that is public knowledge
- your client secret, a random string that you should keep secret
- the public key from the IdP you are using. Each IdP instance must use a
  different private/public key pair.
- (optional) the random, session scoped state

In this workflow you allow certain or all users to use your client. Your client
does not need a login page, instead it uses the login page from the IdP. You
can generate the link to the Login page of the IdP using this library:

```
OAuth2Client config = new OAuth2Client();
config.setHost("https://login.mitro.dkfz.de/");
config.setClientId("your-client-id");
config.setClientSecret("your-client-secret");
config.setHostPublicKey("MII....");

String linkUrl = OAuth2ClientConfig.getRedirectUrl(config, scheme,
            serverName, port, contextPath, redirectUrl,
            Scope.OPENID);

```


Where `scheme`, `serverName`, `port` and `contextPath` are values from the request, whereas
`redirectUrl` is a relative URL in your application, e.g. "/login.xhtml".

This method will generate a URL like this:

```
https://login.mitro.dkfz.de/grant.xhtml?client_id=your-client-id&scope=openid&redirect_uri=https%3A%2F%2Fyour-host%2FsamplyLogin.xhtml
```

It is recommended to store the configuration values in a file, that is not accesible to other users, e.g.
in an XML file. You can then load the configuration file with the `JAXBUtil`:

```
OAuth2Client config = JAXBUtil.unmarshall(File file, context, OAuth2Client.class);
```

Where `file` is the file with the OAuth2Client XML, see below. You can generate a JAXBContext with `JAXBContext.newInstance(OAuth2Client.class)`.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<oAuth2Client
    xmlns="http://schema.samply.de/config/OAuth2Client"
    xmlns:xml="http://www.w3.org/XML/1998/namespace"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://schema.samply.de/config/OAuth2Client http://schema.samply.de/config/OAuth2Client.xsd">

    <host>https://the.samply.auth.url/</host>
    <hostPublicKey>
MIICI...
    </hostPublicKey>
    <clientId>your-client-id</clientId>
    <clientSecret>your-client-secret</clientSecret>
</oAuth2Client>
```


If the user clicks on the generated link he will see a login page, if he didn't login yet. After he has
logged in he will be redirected back to your web application with an additional request
parameter, the code:

```
https://your-host/samplyLogin.xhtml?code=a-random-code
```

Your application can now use this code in combination with your client ID and client secret
to get an access token, ID token and refresh token. All tokens have a limited lifetime and a different purpose:

- use the access token to access other applications via their respective REST interface
- use the ID token to identify the user, e.g. get his real name
- use the refresh token to renew your access token

You can use this library to make the finishing call:

```
AuthClient client = new AuthClient(config, "a-random-code", client);
JWTAccessToken accessToken = client.getAccessToken();
JWTIDToken idToken = client.getIDToken();
```

This method will check if the tokens are valid and so on, and return the access token
if everything is fine.

### Your client has a private key (RSA)

In this case your client always acts on behalf of exactly one user. This user is
always the same and has registered a public key in the IdP. In this case you need
to sign a random code with your private key in order to get an access token and ID token (you will never get a
refresh token using a private key).

Use the AuthClient to get a new access token:

```
AuthClient client = new AuthClient(authUrl, publicKey,
    yourPrivateKey, client);
JWTAccessToken token = client.getAccessToken();
```

## License

Copyright 2020 The Samply Development Community

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
