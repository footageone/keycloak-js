import {KeycloakRoles} from "./roles";

export interface KeycloakResourceAccess {
    [key: string]: KeycloakRoles
}
