import { Permission } from 'accesscontrol/lib/core/Permission';

interface AclPermissionParams {
    action: string;
    roles: string[];
    granted: boolean;
    resource: string;
    attributes: string[];
}

export class AclPermission extends Permission {
    readonly roles: string[];
    readonly granted: boolean;
    readonly resource: string;
    readonly attributes: string[];
    constructor(params: AclPermissionParams) {
        super(
            {},
            {
                action: params.action,
                resource: params.resource,
                role: params.roles,
                possession: '',
            }
        );
        this.roles = params.roles;
        this.granted = params.granted;
        this.resource = params.resource;
        this.attributes = params.attributes;
    }
    public filter(_data: any): any {}
}
