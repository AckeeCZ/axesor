import { intersection, pick } from 'ramda';

interface AclPermissionParams {
    action: string;
    roles: string[];
    granted: boolean;
    resource: string;
    attributes: string[];
}

export class AclPermission {
    readonly roles: string[];
    readonly granted: boolean;
    readonly resource: string;
    readonly attributes: string[];
    constructor(params: AclPermissionParams) {
        this.roles = params.roles;
        this.granted = params.granted;
        this.resource = params.resource;
        this.attributes = params.attributes;
    }
    public filter(data: any): any {
        if (this.attributes[0] === '*') {
            return data;
        }
        return pick(intersection(Object.keys(data), this.attributes), data);
    }
}
