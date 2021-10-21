import {KeycloakRoles} from "./roles";
import {KeycloakResourceAccess} from "./resource-access";

export interface KeycloakTokenParsed {
    exp?: number;
    iat?: number;
    nonce?: string;
    sub?: string;
    session_state?: string;
    realm_access?: KeycloakRoles;
    resource_access?: KeycloakResourceAccess;
}
