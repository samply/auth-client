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

import de.samply.auth.rest.RegistrationRequestDto;
import de.samply.auth.rest.UserDto;
import de.samply.auth.rest.UserListDto;
import de.samply.auth.rest.Usertype;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

public class AuthClientUtils {

  /**
   * TODO: add javadoc.
   */
  public static UserRepresentation samplyRegistrationToKeycloak(
      RegistrationRequestDto samplyUser, String password) {
    UserRepresentation keycloakUser = new UserRepresentation();
    keycloakUser.setEmail(samplyUser.getEmail());
    keycloakUser.setEmailVerified(true);
    keycloakUser.setUsername(samplyUser.getName());
    keycloakUser.setEnabled(true);
    Map<String, List<String>> attributes = new HashMap<>();
    attributes.put(
        "usertype", Collections.singletonList(samplyUserTypeToKeycloak(samplyUser.getUsertype())));
    attributes.put("description", Collections.singletonList(samplyUser.getDescription()));
    keycloakUser.setAttributes(attributes);

    CredentialRepresentation credentials = new CredentialRepresentation();
    credentials.setTemporary(false);
    credentials.setType("password");
    credentials.setValue(password);
    keycloakUser.setCredentials(Collections.singletonList(credentials));
    return keycloakUser;
  }

  /**
   * TODO: add javadoc.
   */
  public static UserDto keycloakUserToSamply(UserRepresentation keycloakUser) {
    UserDto samplyUser = new UserDto();
    // TODO map missing fields ?
    //            samplyUser.setContactInformation();
    samplyUser.setEmail(keycloakUser.getEmail());
    samplyUser.setEmailVerified(keycloakUser.isEmailVerified());
    //            samplyUser.setExternalLabel();
    samplyUser.setId(keycloakUser.getId());
    //            samplyUser.setLocations();
    samplyUser.setName(keycloakUser.getFirstName() + " " + keycloakUser.getLastName());
    return samplyUser;
  }

  /**
   * TODO: add javadoc.
   */
  public static UserListDto keycloakUsersToSamply(UserRepresentation[] keycloakUsers) {
    UserListDto userList = new UserListDto();
    List<UserDto> samplyUsers = new ArrayList<>();

    for (UserRepresentation keycloakUser : keycloakUsers) {
      samplyUsers.add(keycloakUserToSamply(keycloakUser));
    }

    userList.setUsers(samplyUsers);
    return userList;
  }

  /**
   * TODO: add javadoc.
   */
  public static String samplyUserTypeToKeycloak(Usertype usertype) {
    switch (usertype) {
      case OSSE_REGISTRY:
        return KeycloakUsertype.OSSE_REGISTRY;
      case NORMAL:
        return KeycloakUsertype.NORMAL;
      case BRIDGEHEAD:
        return KeycloakUsertype.BRIDGEHEAD;
      default:
        return null;
    }
  }
}
