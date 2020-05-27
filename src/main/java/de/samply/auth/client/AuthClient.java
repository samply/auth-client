/*
 * Copyright (C) 2015 Working Group on Joint Research, University Medical Center Mainz
 * Copyright (C) since 2016 The Samply Community
 *
 * <p>This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU Affero General Public License as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * <p>You should have received a copy of the GNU Affero General Public License along with this
 * program; if not, see <http://www.gnu.org/licenses>.
 *
 * <p>Additional permission under GNU GPL version 3 section 7:
 *
 * <p>If you modify this Program, or any covered work, by linking or combining it with Jersey
 * (https://jersey.java.net) (or a modified version of that library), containing parts covered by
 * the terms of the General Public License, version 2.0, the licensors of this Program grant you
 * additional permission to convey the resulting work.
 */

package de.samply.auth.client;

import de.samply.auth.client.jwt.JwtAccessToken;
import de.samply.auth.client.jwt.JwtException;
import de.samply.auth.client.jwt.JwtIdToken;
import de.samply.auth.client.jwt.JwtRefreshToken;
import de.samply.auth.rest.AccessTokenDto;
import de.samply.auth.rest.ClientListDto;
import de.samply.auth.rest.LocationDto;
import de.samply.auth.rest.OAuth2Discovery;
import de.samply.auth.rest.UserListDto;
import de.samply.common.config.OAuth2Client;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.Response;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The AuthClient provides a convenient way to communicate with the Samply Auth identitiy provider.
 * There are four different constructors, each of them requires different arguments.
 *
 * <pre>
 * 1. Use your client ID, secret and a code, when your application is a well-known client
 * 2. Use your private key if the public key has been registered in the identity provider
 * 3. Use your access token, ID token and refresh token if you already have them
 * 4. Use your Access token and private key, if you already have an access token
 * </pre>
 */
public abstract class AuthClient {

  protected final Logger logger = LoggerFactory.getLogger(getClass());

  /** The Auth base URL. */
  protected String baseUrl;

  /** The access token returned from the identity provider. */
  protected JwtAccessToken accessToken;

  /** The ID token returned from the identity provider. */
  protected JwtIdToken idToken;

  /** The refresh token returned from the identity provider. */
  protected JwtRefreshToken refreshToken;

  /** OAuth2 configuration. */
  protected OAuth2Client config;

  /** The Auths public key that is used to verify the signature. */
  protected PublicKey publicKey;

  /** The private key. Optional. */
  protected PrivateKey privateKey;

  /** The code. Optional. */
  protected String code;

  /** The Jersey Client used in this Auth Client. */
  protected Client client;

  /** The state used for identity provider. */
  protected String state;

  /** The redirect URL tat the identity provider should redirect to. */
  protected String redirectUrl;

  protected String grantType;

  protected String username;

  protected String password;

  public AuthClient() {}

  /**
   * TODO: add javadoc.
   */
  public AuthClient(
      String baseUrl,
      JwtAccessToken accessToken,
      JwtIdToken idToken,
      JwtRefreshToken refreshToken,
      OAuth2Client config,
      PublicKey publicKey,
      PrivateKey privateKey,
      String code,
      Client client,
      String state,
      String redirectUrl,
      String grantType,
      String username,
      String password) {
    this.baseUrl = baseUrl;
    this.accessToken = accessToken;
    this.idToken = idToken;
    this.refreshToken = refreshToken;
    this.config = config;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    this.code = code;
    this.client = client;
    this.state = state;
    this.redirectUrl = redirectUrl;
    this.grantType = grantType;
    this.username = username;
    this.password = password;
  }

  /**
   * Returns the access token for this Auth Client. Requests a new one if necessary.
   */
  public JwtAccessToken getAccessToken() throws InvalidTokenException {
    try {
      if (accessToken == null || !accessToken.isValid()) {
        getNewAccessToken();
      }
      return accessToken;
    } catch (JwtException e) {
      logger.debug("This should never happen.");
      return null;
    }
  }

  /**
   * Returns the ID token for this Auth Client. Requests a new one if necessary.
   */
  public JwtIdToken getIdToken() throws InvalidTokenException {
    if (refreshToken == null) {
      return null;
    } else {
      try {
        if (idToken == null) {
          getNewAccessToken();
        }

        return idToken;
      } catch (JwtException e) {
        logger.debug("This should never happen.");
        return null;
      }
    }
  }

  protected JwtAccessToken getRestAccessToken() {
    try {
      logger.debug("Requesting new access token, base URL: " + baseUrl);
      logger.debug("This is a client with an ID, a secret and a code.");

      Invocation.Builder builder = getAccessTokenBuilder();
      Form form = new Form();
      form.param("grant_type", "client_credentials");
      form.param("client_id", config.getClientId());
      form.param("client_secret", config.getClientSecret());
      AccessTokenDto tokenDto = builder.post(Entity.form(form), AccessTokenDto.class);
      // here we want our own tokens for the rest user
      JwtAccessToken accessToken = new JwtAccessToken(publicKey, tokenDto.getAccessToken());

      if (!accessToken.isValid()) {
        logger.debug("The token we got was not valid. Throw an exception.");
        throw new InvalidTokenException();
      }

      logger.debug("Got new valid access token for rest user using a code!");

      return accessToken;
    } catch (InvalidTokenException | JwtException e) {
      logger.debug("Retrieving rest access token failed.");
      logger.debug(e.toString());
      return null;
    }
  }

  protected abstract JwtAccessToken getNewAccessToken() throws JwtException, InvalidTokenException;

  /**
   * Returns the authorization header, that will be used with this auth client.
   */
  protected String getAuthorizationHeader() {
    if (accessToken != null) {
      return accessToken.getHeader();
    } else {
      return "Basic "
          + Base64.encodeBase64String(
              (config.getClientId() + ":" + config.getClientSecret()).getBytes());
    }
  }

  /**
   * Searches for users using the given string.
   */
  public abstract UserListDto searchUser(String input) throws InvalidTokenException;

  /**
   * Returns a list of all locations.
   */
  public abstract List<LocationDto> getLocations();

  /**
   * Registers the registry in an Auth identity provider.
   */
  public abstract Response register(RegistrationWrapper wrapper);

  protected abstract Invocation.Builder getClientBuilder();

  /**
   * Returns a List of currently active clients.
   */
  public ClientListDto getClients() {
    return getClientBuilder().get(ClientListDto.class);
  }

  /**
   * Returns the Builder to get an access token.
   */
  protected abstract Invocation.Builder getAccessTokenBuilder();

  public abstract OAuth2Discovery getDiscovery();

  public String getState() {
    return state;
  }

  public void setState(String state) {
    this.state = state;
  }

  public String getRedirectUrl() {
    return redirectUrl;
  }

  public void setRedirectUrl(String redirectUrl) {
    this.redirectUrl = redirectUrl;
  }

  public OAuth2Client getConfig() {
    return config;
  }

  public void setConfig(OAuth2Client config) {
    this.config = config;
  }

  /**
   * Returns the refresh token. May be null.
   */
  public JwtRefreshToken getRefreshToken() {
    return refreshToken;
  }

  public String getGrantType() {
    return grantType;
  }

  public void setGrantType(String grantType) {
    this.grantType = grantType;
  }

  public PublicKey getPublicKey() {
    return publicKey;
  }

  public void setPublicKey(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  public void setPrivateKey(PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  public String getCode() {
    return code;
  }

  public void setCode(String code) {
    this.code = code;
  }

  public Client getClient() {
    return client;
  }

  public void setClient(Client client) {
    this.client = client;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }
}
