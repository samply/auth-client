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

import de.samply.auth.client.jwt.*;
import de.samply.auth.rest.*;
import de.samply.auth.utils.OAuth2ClientConfig;
import de.samply.common.config.OAuth2Client;
import org.glassfish.jersey.client.ClientResponse;
import org.keycloak.representations.idm.UserRepresentation;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;

public class KeycloakAuthClient extends AuthClient {

    public KeycloakAuthClient(JWTAccessToken accessToken, JWTIDToken idToken, JWTRefreshToken refreshToken, OAuth2Client config,
                            Client client, String state) {
        super(config.getHost(), accessToken, idToken, refreshToken, config, KeyLoader.loadKey(config.getHostPublicKey()),null,
            null, client, state, null, null, null, null);
    }

    public KeycloakAuthClient(String code, OAuth2Client config, Client client, String state) {
        super(config.getHost(), null, null, null, config, KeyLoader.loadKey(config.getHostPublicKey()), null,
            code, client, state, null, null, null, null);
    }

    public KeycloakAuthClient(OAuth2Client config, Client client, String state) {
        super(config.getHost(), null, null, null, config, KeyLoader.loadKey(config.getHostPublicKey()), null,
            null, client, state, null, null, null, null);
    }

    public KeycloakAuthClient(OAuth2Client config, Client client) {
        super(config.getHost(), null, null, null, config, KeyLoader.loadKey(config.getHostPublicKey()), null,
            null, client, null, null, null, null, null);
    }

    /**
     * Returns a List of currently active clients.
     *
     * @return
     */
    public ClientListDTO getClients() {
        return getClientBuilder().get(ClientListDTO.class);
    }

    /**
     * Searches for users using the given string.
     *
     * @param input
     * @return
     * @throws InvalidKeyException
     * @throws InvalidTokenException
     */
    public UserListDTO searchUser(String input) {
        UserRepresentation[] keycloakUsers = getUserBuilder(input).header("Authorization", getRestAccessToken().getHeader()).get(UserRepresentation[].class);
        return AuthClientUtils.keycloakUsersToSamply(keycloakUsers);
    }

    /**
     * Returns a list of all locations.
     *
     * @return
     * @throws InvalidKeyException
     * @throws InvalidTokenException
     */
    public List<LocationDTO> getLocations() {
        return getLocationsBuilder().header("Authorization", getAuthorizationHeader()).get(LocationListDTO.class).getLocations();
    }

    public Response register(RegistrationWrapper wrapper) {
        UserRepresentation user = wrapper.getUsrRep();
        if (user == null) {
            return null;
        }
        return getRegisterBuilder().header("Authorization", getRestAccessToken().getHeader()).post(Entity.json(user));
    }

    /**
     * Explicitly requests a new Access token. This is a blocking call. Use this method only if necessary.
     *
     * @return
     * @throws JWTException
     * @throws InvalidTokenException
     * @throws InvalidKeyException
     */
    protected JWTAccessToken getNewAccessToken() throws JWTException, InvalidTokenException {
        logger.debug("Requesting new access token, base URL: " + baseUrl);

        Invocation.Builder builder = getAccessTokenBuilder();
        AccessTokenDTO tokenDTO;

        Form form = new Form();
        if (refreshToken != null) {
            form.param("refresh_token", refreshToken.getSerialized());
        } else if (code != null) { // TODO to save at least some compatibility to samply auth... this is crap :)
            form.param("grant_type", GrantType.AUTHORIZATION_CODE);
            form.param("code", code);
            form.param("redirect_uri", redirectURL);
            form.param("client_id", config.getClientId());
            form.param("client_secret", config.getClientSecret());
            form.param("state", state);
        } else if (grantType.equals(GrantType.CLIENT_CREDENTIALS)) {
            form.param("grant_type", grantType);
            form.param("client_id", config.getClientId());
            form.param("client_secret", config.getClientSecret());
            form.param("scope", "openid");
        } else if (grantType.equals(GrantType.PASSWORD)){
            form.param("grant_type", grantType);
            form.param("client_id", config.getClientId());
            form.param("client_secret", config.getClientSecret());
            form.param("username", username);
            form.param("password", password);
            form.param("scope", "openid");
        }
        tokenDTO = builder.post(Entity.form(form), AccessTokenDTO.class);

        accessToken = new JWTAccessToken(publicKey, tokenDTO.getAccessToken());
        idToken = new JWTIDToken(config.getClientId(), publicKey, tokenDTO.getIdToken());
        refreshToken = new JWTRefreshToken(publicKey, tokenDTO.getRefreshToken());

        if (!accessToken.isValid() || !idToken.isValid() || !refreshToken.isValid()) {
            logger.debug("The token we got was not valid. Throw an exception.");
            throw new InvalidTokenException();
        }

        logger.debug("Got new valid access token using a code!");

        return this.accessToken;
    }

    /**
     * Returns the current OAuth2 configuration.
     */
    public OAuth2Discovery getDiscovery() {
        return getDiscoveryBuilder().get(OAuth2Discovery.class);
    }

    private WebTarget getUriPrefix() {
        return client.target(baseUrl).path(OAuth2ClientConfig.getEndpointPrefix(config.getRealm()));
    }

    protected Invocation.Builder getAccessTokenBuilder() {
        return getUriPrefix().path("token").request(MediaType.APPLICATION_JSON);
    }

    private Invocation.Builder getRegisterBuilder() {
        return client.target(baseUrl).path("admin").path("realms").path(config.getRealm()).path("users").request(MediaType.APPLICATION_JSON);
    }

    private Invocation.Builder getDiscoveryBuilder() {
        return getUriPrefix().path(".well-known").path("openid-configuration").request(MediaType.APPLICATION_JSON);
    }

    /**
     * Returns the Builder to search for users.
     */
    private Invocation.Builder getUserBuilder(String input) {
        return client.target(baseUrl).path("admin").path("realms").path(config.getRealm()).path("users")
            .queryParam("search", input).request(MediaType.APPLICATION_JSON);
    }

    // TODO keycloak is not done
    private Invocation.Builder getLocationsBuilder() {
        return getUriPrefix().path("???").request(MediaType.APPLICATION_JSON);
    }

    /**
     * Returns the Builder to get all clients.
     * TODO keycloak is not done
     */
    protected Invocation.Builder getClientBuilder() {
        return getUriPrefix().path("token").request(MediaType.APPLICATION_JSON);
    }
}
