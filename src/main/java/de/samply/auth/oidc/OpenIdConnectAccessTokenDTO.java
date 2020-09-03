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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.io.Serializable;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * Requests a new Access Token from the OpenId Connect identity provider.
 */

@XmlRootElement
@JsonIgnoreProperties(ignoreUnknown = true)
public class OpenIdConnectAccessTokenDTO implements Serializable {

  private static final long serialVersionUID = 1L;

  private String accessToken;

  private String type;

  private int expiresIn;

  private String refreshToken;

  private String idToken;

  /**
   * @return the accessToken
   */
  @XmlElement(name = "access_token")
  public String getAccessToken() {
    return accessToken;
  }

  /**
   * @param accessToken the accessToken to set
   */
  public void setAccessToken(String accessToken) {
    this.accessToken = accessToken;
  }

  /**
   * @return the type
   */
  @XmlElement(name = "token_type")
  public String getType() {
    return type;
  }

  /**
   * @param type the type to set
   */
  public void setType(String type) {
    this.type = type;
  }

  /**
   * @return the expires_in
   */
  @XmlElement(name = "expires_in")
  public int getExpiresIn() {
    return expiresIn;
  }

  /**
   * @param expires_in the expires_in to set
   */
  public void setExpiresIn(int expires_in) {
    this.expiresIn = expires_in;
  }

  @XmlElement(name = "refresh_token")
  public String getRefreshToken() {
    return refreshToken;
  }

  public void setRefreshToken(String refreshToken) {
    this.refreshToken = refreshToken;
  }

  @XmlElement(name = "id_token")
  public String getIdToken() {
    return idToken;
  }

  public void setIdToken(String idToken) {
    this.idToken = idToken;
  }
}
