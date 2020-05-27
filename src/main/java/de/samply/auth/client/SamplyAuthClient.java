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
import de.samply.common.config.OAuth2Client;
import org.apache.commons.codec.binary.Base64;
import org.glassfish.jersey.client.ClientResponse;
import org.keycloak.representations.idm.UserRepresentation;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.PrivateKey;
import java.util.List;

public class SamplyAuthClient extends AuthClient {

    /**
     * The OAuth2 API URL PATH
     */
    private static final String OAUTH2_PATH = "oauth2";

    public SamplyAuthClient(JWTAccessToken accessToken, JWTIDToken idToken, JWTRefreshToken refreshToken, OAuth2Client config,
                      Client client, String state) {
        super(config.getHost(), accessToken, idToken, refreshToken, config, KeyLoader.loadKey(config.getHostPublicKey()),
            null, null, client, state, null, null, null, null);
    }

    public SamplyAuthClient(String code, OAuth2Client config, Client client, String state) {
        super(config.getHost(), null, null, null, config, KeyLoader.loadKey(config.getHostPublicKey()), null,
            code, client, state, null, null, null, null);
    }

    public SamplyAuthClient(PrivateKey privKey, OAuth2Client config, Client client, String state) {
        super(config.getHost(), null, null, null, config, KeyLoader.loadKey(config.getHostPublicKey()), privKey,
            null, client, state, null, null, null, null);
    }

    /**
     * Returns the ID token for this Auth Client. Requests a new one if necessary.
     *
     * @return
     * @throws InvalidTokenException
     * @throws InvalidKeyException
     */
    public JWTIDToken getIDToken() throws InvalidTokenException {
        if (code == null) {
            return null;
        }
        return super.getIDToken();
    }

    /**
     * Searches for users using the given string.
     *
     * @param input
     * @return
     * @throws InvalidKeyException
     * @throws InvalidTokenException
     */
    public UserListDTO searchUser(String input) throws InvalidTokenException {
        return getUserBuilder(input).header("Authorization", getAccessToken().getHeader()).get(UserListDTO.class);
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
        RegistrationRequestDTO dto = wrapper.getRegReq();
        if (dto == null) {
            return null;
        }
        dto.setBase64EncodedPublicKey(Base64.encodeBase64String(KeyLoader.loadPublicRSAKey(privateKey).getEncoded()));
        return getRegisterBuilder().accept(MediaType.APPLICATION_JSON).post(Entity.json(dto));
    }

    protected JWTAccessToken getNewAccessToken() throws JWTException, InvalidTokenException {
        /**
         * If this is a client with a code, id and secret
         */
        logger.debug("Requesting new access token, base URL: " + baseUrl);

        Invocation.Builder builder = getAccessTokenBuilder();
        AccessTokenDTO tokenDTO;

        AccessTokenRequestDTO dto = new AccessTokenRequestDTO();
        if (refreshToken == null) {
            logger.debug("No refresh token available yet");
            dto.setClientId(config.getClientId());
            dto.setClientSecret(config.getClientSecret());
            dto.setCode(code);
        } else {
            logger.debug("Using the refresh token");
            dto.setRefreshToken(refreshToken.getSerialized());
        }
        tokenDTO = builder.post(Entity.json(dto), AccessTokenDTO.class);

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
        return client.target(baseUrl).path(OAUTH2_PATH);
    }

    protected Invocation.Builder getAccessTokenBuilder() {
        return getUriPrefix().path("access_token").request(MediaType.APPLICATION_JSON);
    }

    private Invocation.Builder getRegisterBuilder() {
        return getUriPrefix().path("register").request(MediaType.APPLICATION_JSON);
    }

    private Invocation.Builder getDiscoveryBuilder() {
        return getUriPrefix().path(".well-known").path("openid-configuration").request(MediaType.APPLICATION_JSON);
    }

    /**
     * Returns the Builder to search for users.
     */
    private Invocation.Builder getUserBuilder(String input) {
        return getUriPrefix().path("users").path("search")
            .queryParam("query", input).request(MediaType.APPLICATION_JSON);
    }

    private Invocation.Builder getLocationsBuilder() {
        return getUriPrefix().path("locations").request(MediaType.APPLICATION_JSON);
    }

    /**
     * Returns the Builder to get all clients.
     */
    protected Invocation.Builder getClientBuilder() {
        return getUriPrefix().path("clients").request(MediaType.APPLICATION_JSON);
    }
}
