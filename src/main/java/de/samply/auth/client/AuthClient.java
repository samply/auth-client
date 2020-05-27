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

import de.samply.auth.client.jwt.*;
import de.samply.auth.rest.*;
import de.samply.common.config.OAuth2Client;
import org.apache.commons.codec.binary.Base64;
import org.glassfish.jersey.client.ClientResponse;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.keycloak.representations.idm.UserRepresentation;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.Response;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

/**
 * The AuthClient provides a convenient way to communicate with the Samply Auth identitiy
 * provider. There are four different constructors, each of them requires different
 * arguments.
 * <p>
 * <pre>
 * 1. Use your client ID, secret and a code, when your application is a well-known client
 * 2. Use your private key if the public key has been registered in the identity provider
 * 3. Use your access token, ID token and refresh token if you already have them
 * 4. Use your Access token and private key, if you already have an access token
 * </pre>
 */
public abstract class AuthClient {

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * The Auth base URL.
     */
    protected String baseUrl;

    /**
     * The access token returned from the identity provider.
     */
    protected JWTAccessToken accessToken;

    /**
     * The ID token returned from the identity provider.
     */
    protected JWTIDToken idToken;

    /**
     * The refresh token returned from the identity provider.
     */
    protected JWTRefreshToken refreshToken;

    /**
     * OAuth2 configuration
     */
    protected OAuth2Client config;

    /**
     * The Auths public key that is used to verify the signature.
     */
    protected PublicKey publicKey;

    /**
     * The private key. Optional.
     */
    protected PrivateKey privateKey;

    /**
     * The code. Optional.
     */
    protected String code;

    /**
     * The Jersey Client used in this Auth Client.
     */
    protected Client client;

    /**
     * The state used for identity provider.
     */
    protected String state;

    /**
     * The redirect URL tat the identity provider should redirect to.
     */
    protected String redirectURL;

    protected String grantType;

    protected String username;

    protected String password;

    public AuthClient() {
    }

    public AuthClient(String baseUrl, JWTAccessToken accessToken, JWTIDToken idToken, JWTRefreshToken refreshToken,
                      OAuth2Client config, PublicKey publicKey, PrivateKey privateKey, String code, Client client,
                      String state, String redirectURL, String grantType, String username, String password) {
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
        this.redirectURL = redirectURL;
        this.grantType = grantType;
        this.username = username;
        this.password = password;
    }

    /**
     * Returns the access token for this Auth Client. Requests a new one if necessary.
     *
     * @return
     * @throws InvalidTokenException
     * @throws InvalidKeyException
     */
    public JWTAccessToken getAccessToken() throws InvalidTokenException {
        try {
            if (accessToken == null || !accessToken.isValid()) {
                getNewAccessToken();
            }
            return accessToken;
        } catch (JWTException e) {
            logger.debug("This should never happen.");
            return null;
        }
    }

    /**
     * Returns the ID token for this Auth Client. Requests a new one if necessary.
     *
     * @return
     * @throws InvalidTokenException
     * @throws InvalidKeyException
     */
    public JWTIDToken getIDToken() throws InvalidTokenException {
        if (refreshToken == null) {
            return null;
        } else {
            try {
                if (idToken == null) {
                    getNewAccessToken();
                }

                return idToken;
            } catch (JWTException e) {
                logger.debug("This should never happen.");
                return null;
            }
        }
    }

    protected JWTAccessToken getRestAccessToken() {
        try {
            logger.debug("Requesting new access token, base URL: " + baseUrl);
            logger.debug("This is a client with an ID, a secret and a code.");

            Invocation.Builder builder = getAccessTokenBuilder();
            AccessTokenDTO tokenDTO;
            Form form = new Form();
            form.param("grant_type", "client_credentials");
            form.param("client_id", config.getClientId());
            form.param("client_secret", config.getClientSecret());
            tokenDTO = builder.post(Entity.form(form), AccessTokenDTO.class);
            // here we want our own tokens for the rest user
            JWTAccessToken accessToken = new JWTAccessToken(publicKey, tokenDTO.getAccessToken());

            if (!accessToken.isValid()) {
                logger.debug("The token we got was not valid. Throw an exception.");
                throw new InvalidTokenException();
            }

            logger.debug("Got new valid access token for rest user using a code!");

            return accessToken;
        } catch (InvalidTokenException | JWTException e) {
            logger.debug("Retrieving rest access token failed.");
            logger.debug(e.toString());
            return null;
        }
    }

    protected abstract JWTAccessToken getNewAccessToken() throws JWTException, InvalidTokenException;

    /**
     * Returns the authorization header, that will be used with this auth client.
     *
     * @return
     */
    protected String getAuthorizationHeader() {
        if (accessToken != null) {
            return accessToken.getHeader();
        } else {
            return "Basic " + Base64.encodeBase64String((config.getClientId() + ":" + config.getClientSecret()).getBytes());
        }
    }

    /**
     * Searches for users using the given string.
     *
     * @param input
     * @return
     * @throws InvalidKeyException
     * @throws InvalidTokenException
     */
    public abstract UserListDTO searchUser(String input) throws InvalidTokenException;

    /**
     * Returns a list of all locations.
     *
     * @return
     * @throws InvalidKeyException
     * @throws InvalidTokenException
     */
    public abstract List<LocationDTO> getLocations();

    /**
     * Registers the registry in an Auth identity provider.
     *
     * @param wrapper
     * @return
     */
    public abstract Response register(RegistrationWrapper wrapper);

    protected abstract Invocation.Builder getClientBuilder();

    /**
     * Returns a List of currently active clients.
     *
     * @return
     */
    public ClientListDTO getClients() {
        return getClientBuilder().get(ClientListDTO.class);
    }

    /**
     * Returns the Builder to get an access token.
     *
     * @return
     */
    protected abstract Invocation.Builder getAccessTokenBuilder();

    public abstract OAuth2Discovery getDiscovery();

    public String getState() {
        return state;
    }

    public String getRedirectURL() {
        return redirectURL;
    }

    public void setRedirectURL(String redirectURL) {
        this.redirectURL = redirectURL;
    }

    public OAuth2Client getConfig() {
        return config;
    }

    /**
     * Returns the refresh token. May be null.
     *
     * @return
     */
    public JWTRefreshToken getRefreshToken() {
        return refreshToken;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public void setConfig(OAuth2Client config) {
        this.config = config;
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

    public void setState(String state) {
        this.state = state;
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
