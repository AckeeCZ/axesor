import { assocPath, path, values } from 'ramda';
const jp = require('jsonpath');

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
        const result = this.attributes
            .map(attribute => jp.paths(data, `$..${attribute}`))
            .reduce((a, b) => a.concat(b), [])
            .map((jpPath: string[]) => jpPath.slice(1))
            .map((jpPath: string[]) => [jpPath, path(jpPath, data)])
            .reduce((acc: any, [jpPath, data]: [string[], any]) => assocPath(jpPath, data, acc), {});
        if (Array.isArray(data)) {
            return values(result);
        }
        return result;
    }
}
