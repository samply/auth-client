/*
 * Copyright (C) 2018 The Samply Community
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 *
 * Additional permission under GNU GPL version 3 section 7:
 *
 * If you modify this Program, or any covered work, by linking or combining it
 * with Jersey (https://jersey.java.net) (or a modified version of that
 * library), containing parts covered by the terms of the General Public
 * License, version 2.0, the licensors of this Program grant you additional
 * permission to convey the resulting work.
 */

package de.samply.auth.oidc;

import de.samply.auth.client.jwt.JwtAccessToken;
import de.samply.auth.client.jwt.JwtException;
import de.samply.auth.rest.UserDto;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A simple OpenId Connect client.
 */
// TODO: Introduce superclass 'AbstractOpenIdConnectClient' and use it for OpenIdConnectClient and
//       AdfsClient
//       Resolve the Bitbucket project for ADFS client
public class OpenIdConnectClient {

  /**
   * The Authorization header.
   */
  private static final String AUTHORIZATION_HEADER = "Authorization";
  private static Logger logger = LoggerFactory.getLogger(OpenIdConnectClient.class);
  /**
   * The OpenId Connect URL, e.g. 'https://perun.example.org/'.
   */
  private String url;
  /**
   * Provider specific extension, e.g. 'oauth2/' or 'oidc/'.
   */
  private String urlExt;
  /**
   * The OpenId Connect public key that is used to verify the signature from the access token.
   */
  private String publicKey;
  /**
   * Your client ID.
   */
  private String clientId;
  /**
   * Your client secret.
   */
  private String clientSecret;
  /**
   * The HTTP client that will be used.
   */
  private Client client;

  /**
   * Initializes a new OpenId Connect client.
   */
  public OpenIdConnectClient(String url, String urlExt, String publicKey, String clientId,
      String clientSecret, Client client) {
    this.setUrl(url);
    this.setUrlExt(urlExt);
    this.publicKey = publicKey;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.client = client;
  }

  /**
   * Calls the userinfo resource from perun.
   *
   * @return UserDto
   */
  public UserDto getNewUserInfo(String authorizationHeader) {
    UserDto userDto = client.target(getBaseUrl()).path("userinfo")
        .request(MediaType.APPLICATION_JSON).header(AUTHORIZATION_HEADER, authorizationHeader)
        .get(UserDto.class);

    return userDto;
  }

  /**
   * Returnes the redirect URL to the OpenId Connect identity provider.
   */
  public String getRedirectUrl(String localRedirectUrl) {
    StringBuilder builder = new StringBuilder(getBaseUrl());

    builder.append("authorize?");
    try {
      builder.append("scope=openid+email+profile+groupNames");
      builder.append("&redirect_uri=")
          .append(URLEncoder.encode(localRedirectUrl, StandardCharsets.UTF_8.displayName()));
      builder.append("&client_id=")
          .append(URLEncoder.encode(clientId, StandardCharsets.UTF_8.displayName()));
      builder.append("&client_secret=")
          .append(URLEncoder.encode(clientSecret, StandardCharsets.UTF_8.displayName()));
      builder.append("&response_type=code");

      logger.debug("Redirect URL: " + builder.toString());

      return builder.toString();
    } catch (UnsupportedEncodingException e) {
      e.printStackTrace();
    }
    return null;
  }

  /**
   * Todo Javadoc.
   */
  public String getBaseUrl() {
    String resultUrl;
    if (!url.endsWith("/") && !urlExt.startsWith("/")) {
      resultUrl = url + "/" + urlExt;
    } else if (url.endsWith("/") && urlExt.startsWith("/")) {
      resultUrl = url + urlExt.substring(1);
    } else {
      resultUrl = url + urlExt;
    }

    if (!resultUrl.endsWith("/")) {
      resultUrl += "/";
    }

    return resultUrl;
  }

  /**
   * Gets a new identity token from the OpenId Connect identity provider.
   */
  public OpenIdConnectAccessTokenDto getAccessTokenDto(String code, String localRedirectUrl)
      throws JwtException {
    WebTarget target = client.target(getBaseUrl() + "token");

    MultivaluedHashMap<String, String> values = new MultivaluedHashMap<>();
    values.add("grant_type", "authorization_code");
    values.add("client_id", clientId);
    values.add("client_secret", clientSecret);
    values.add("redirect_uri", localRedirectUrl);
    values.add("code", code);

    OpenIdConnectAccessTokenDto openIdConnectAccessTokenDto = null;
    try {
      openIdConnectAccessTokenDto = target.request(MediaType.APPLICATION_JSON_TYPE)
          .post(Entity.entity(values, MediaType.APPLICATION_FORM_URLENCODED_TYPE),
              OpenIdConnectAccessTokenDto.class);

      return openIdConnectAccessTokenDto;
    } catch (Exception e) {
      e.printStackTrace();
      throw e;
    }
  }

  /**
   * Returns the authorization header, that will be used with this auth client.
   */
  public String getAuthorizationHeader(JwtAccessToken accessToken) {
    if (accessToken != null) {
      return accessToken.getHeader();
    } else {
      return "Basic " + Base64.encodeBase64String((clientId + ":" + clientSecret).getBytes());
    }
  }

  /**
   * Todo: Javadoc.
   * @return the url
   */
  public String getUrl() {
    return url;
  }

  /**
   * Todo: Javadoc.
   * @param url the url to set
   */
  public void setUrl(String url) {
    this.url = url;
  }

  /**
   * Todo: Javadoc.
   * @return the urlExt
   */
  public String getUrlExt() {
    return urlExt;
  }

  /**
   * Todo: Javadoc.
   * @param urlExt the urlExt to set
   */
  public void setUrlExt(String urlExt) {
    this.urlExt = urlExt;
  }

  /**
   * Todo: Javadoc.
   * @return the publicKey
   */
  public String getPublicKey() {
    return publicKey;
  }

  /**
   * Todo: Javadoc.
   * @param publicKey the publicKey to set
   */
  public void setPublicKey(String publicKey) {
    this.publicKey = publicKey;
  }

  /**
   * Todo: Javadoc.
   * @return the clientId
   */
  public String getClientId() {
    return clientId;
  }

  /**
   * Todo: Javadoc.
   * @param clientId the clientId to set
   */
  public void setClientId(String clientId) {
    this.clientId = clientId;
  }
}
