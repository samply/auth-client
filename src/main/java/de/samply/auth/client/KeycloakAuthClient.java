/*
 * Copyright (C) 2018 The Samply Community
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
 * program; if not, see http://www.gnu.org/licenses.
 *
 * <p>Additional permission under GNU GPL version 3 section 7:
 *
 * <p>If you modify this Program, or any covered work, by linking or combining it with Jersey
 * (https://jersey.java.net) (or a modified version of that library), containing parts covered by
 * the terms of the General Public License, version 2.0, the licensors of this Program grant you
 * additional permission to convey the resulting work.
 */

package de.samply.auth.client;

import de.samply.auth.client.jwt.AbstractJwt;
import de.samply.auth.client.jwt.JwtAccessToken;
import de.samply.auth.client.jwt.JwtException;
import de.samply.auth.client.jwt.JwtIdToken;
import de.samply.auth.client.jwt.JwtRefreshToken;
import de.samply.auth.client.jwt.KeyLoader;
import de.samply.auth.rest.AccessTokenDto;
import de.samply.auth.rest.ClientListDto;
import de.samply.auth.rest.LocationDto;
import de.samply.auth.rest.LocationListDto;
import de.samply.auth.rest.OAuth2Discovery;
import de.samply.auth.rest.UserListDto;
import de.samply.auth.utils.OAuth2ClientConfig;
import de.samply.common.config.OAuth2Client;
import java.io.UnsupportedEncodingException;
import java.util.List;
import javax.ws.rs.ProcessingException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.ResponseProcessingException;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.bind.DatatypeConverter;
import net.minidev.json.JSONObject;
import org.keycloak.representations.idm.UserRepresentation;

public class KeycloakAuthClient extends AuthClient {

  /**
   * TODO: add javadoc.
   */
  public KeycloakAuthClient(
      JwtAccessToken accessToken,
      JwtIdToken idToken,
      JwtRefreshToken refreshToken,
      OAuth2Client config,
      Client client,
      String state) {
    super(
        config.getHost(),
        accessToken,
        idToken,
        refreshToken,
        config,
        KeyLoader.loadKey(config.getHostPublicKey()),
        null,
        null,
        client,
        state,
        null,
        null,
        null,
        null);
  }

  /**
   * TODO: add javadoc.
   */
  public KeycloakAuthClient(String code, OAuth2Client config, Client client, String state) {
    super(
        config.getHost(),
        null,
        null,
        null,
        config,
        KeyLoader.loadKey(config.getHostPublicKey()),
        null,
        code,
        client,
        state,
        null,
        null,
        null,
        null);
  }

  /**
   * TODO: add javadoc.
   */
  public KeycloakAuthClient(OAuth2Client config, Client client, String state) {
    super(
        config.getHost(),
        null,
        null,
        null,
        config,
        KeyLoader.loadKey(config.getHostPublicKey()),
        null,
        null,
        client,
        state,
        null,
        null,
        null,
        null);
  }

  /**
   * TODO: add javadoc.
   */
  public KeycloakAuthClient(OAuth2Client config, Client client) {
    super(
        config.getHost(),
        null,
        null,
        null,
        config,
        KeyLoader.loadKey(config.getHostPublicKey()),
        null,
        null,
        client,
        null,
        null,
        null,
        null,
        null);
  }

  /**
   * Returns a List of currently active clients.
   */
  public ClientListDto getClients() {
    return getClientBuilder().get(ClientListDto.class);
  }

  /**
   * Searches for users using the given string.
   */
  public UserListDto searchUser(String input) {
    UserRepresentation[] keycloakUsers =
        getUserBuilder(input)
            .header("Authorization", getRestAccessToken().getHeader())
            .get(UserRepresentation[].class);
    return AuthClientUtils.keycloakUsersToSamply(keycloakUsers);
  }

  /**
   * Returns a list of all locations.
   */
  public List<LocationDto> getLocations() {
    return getLocationsBuilder()
        .header("Authorization", getAuthorizationHeader())
        .get(LocationListDto.class)
        .getLocations();
  }

  /**
   * TODO: add javadoc.
   */
  public Response register(RegistrationWrapper wrapper) {
    UserRepresentation user = wrapper.getUsrRep();
    if (user == null) {
      return null;
    }
    return getRegisterBuilder()
        .header("Authorization", getRestAccessToken().getHeader())
        .post(Entity.json(user));
  }

  /**
   * Explicitly requests a new Access token. This is a blocking call. Use this method only if
   * necessary.
   */
  protected JwtAccessToken getNewAccessToken() throws JwtException, InvalidTokenException {
    logger.debug("Requesting new access token, base URL: " + baseUrl);

    Invocation.Builder builder = getAccessTokenBuilder();

    Form form = new Form();
    if (refreshToken != null) {
      form.param("refresh_token", refreshToken.getSerialized());
    } else if (code
        != null) { // TODO to save at least some compatibility to samply auth... this is crap :)
      form.param("grant_type", GrantType.AUTHORIZATION_CODE);
      form.param("code", code);
      form.param("redirect_uri", redirectUrl);
      form.param("client_id", config.getClientId());
      form.param("client_secret", config.getClientSecret());
      form.param("state", state);
    } else if (grantType.equals(GrantType.CLIENT_CREDENTIALS)) {
      form.param("grant_type", grantType);
      form.param("client_id", config.getClientId());
      form.param("client_secret", config.getClientSecret());
      form.param("scope", "openid");
    } else if (grantType.equals(GrantType.PASSWORD)) {
      form.param("grant_type", grantType);
      form.param("client_id", config.getClientId());
      form.param("client_secret", config.getClientSecret());
      form.param("username", username);
      form.param("password", password);
      form.param("scope", "openid");
    }
    try {
      AccessTokenDto tokenDto = builder.post(Entity.form(form), AccessTokenDto.class);
      accessToken = new JwtAccessToken(publicKey, tokenDto.getAccessToken(), true);
      idToken = new JwtIdToken(config.getClientId(), publicKey, tokenDto.getIdToken(), true);
      refreshToken = new JwtRefreshToken(publicKey, tokenDto.getRefreshToken(), true);

      if (!checkTokenValidity(accessToken) || !checkTokenValidity(idToken) || !checkTokenValidity(
          refreshToken)) {
        logger.debug("The token we got was not valid. Throw an exception.");
        throw new InvalidTokenException();
      }
    } catch (ResponseProcessingException e) {
      logger.error("Error processing the response: " + e.getMessage());
    } catch (ProcessingException e) {
      logger.error("General processing error: " + e.getMessage());
    }
    logger.debug("Got new valid access token using a code!");
    return this.accessToken;
  }

  /**
   * Call keycloaks introspect endpoint.
   * @param token an JWT token (Access, ID or Refresh)
   * @return true if token is active, false otherwise
   */
  private boolean checkTokenValidity(AbstractJwt token) {
    Invocation.Builder builder = getTokenIntrospectionBuilder();
    builder.header("Authorization", getBasicAuthentication());
    Form form = new Form();
    form.param("token", token.getSerialized());
    JSONObject introspectionResult = builder.post(Entity.form(form), JSONObject.class);
    return (boolean) introspectionResult.getOrDefault("active", false);
  }

  /** Returns the current OAuth2 configuration. */
  public OAuth2Discovery getDiscovery() {
    return getDiscoveryBuilder().get(OAuth2Discovery.class);
  }

  private WebTarget getUriPrefix() {
    return client.target(baseUrl).path(OAuth2ClientConfig.getEndpointPrefix(config.getRealm()));
  }

  protected Invocation.Builder getAccessTokenBuilder() {
    return getUriPrefix().path("token").request(MediaType.APPLICATION_JSON);
  }

  protected Invocation.Builder getTokenIntrospectionBuilder() {
    return client
        .target(baseUrl)
        .path(OAuth2ClientConfig.getEndpointPrefix(config.getRealm()))
        .path("token")
        .path("introspect")
        .request(MediaType.APPLICATION_JSON);
  }

  private Invocation.Builder getRegisterBuilder() {
    return client
        .target(baseUrl)
        .path("admin")
        .path("realms")
        .path(config.getRealm())
        .path("users")
        .request(MediaType.APPLICATION_JSON);
  }

  private Invocation.Builder getDiscoveryBuilder() {
    return getUriPrefix()
        .path(".well-known")
        .path("openid-configuration")
        .request(MediaType.APPLICATION_JSON);
  }

  /** Returns the Builder to search for users. */
  private Invocation.Builder getUserBuilder(String input) {
    return client
        .target(baseUrl)
        .path("admin")
        .path("realms")
        .path(config.getRealm())
        .path("users")
        .queryParam("search", input)
        .request(MediaType.APPLICATION_JSON);
  }

  // TODO keycloak is not done
  private Invocation.Builder getLocationsBuilder() {
    return getUriPrefix().path("???").request(MediaType.APPLICATION_JSON);
  }

  /** Returns the Builder to get all clients. TODO keycloak is not done */
  protected Invocation.Builder getClientBuilder() {
    return getUriPrefix().path("token").request(MediaType.APPLICATION_JSON);
  }

  /**
   * Generate BASIC auth header from client id / client secret.
   */
  private String getBasicAuthentication() {
    String token = config.getClientId() + ":" + config.getClientSecret();
    try {
      return "BASIC " + DatatypeConverter.printBase64Binary(token.getBytes("UTF-8"));
    } catch (UnsupportedEncodingException ex) {
      throw new IllegalStateException("Cannot encode with UTF-8", ex);
    }
  }
}
