import jp from 'jsonpath';
import { assocPath, dissocPath, path, values } from 'ramda';

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
        let result = this.attributes
            .filter(attribute => attribute.charAt(0) !== '!')
            .map(attribute => jp.paths(data, `$..${attribute}`))
            .reduce((a, b) => a.concat(b), [])
            .map(jpPath => jpPath.slice(1))
            .map(jpPath => [jpPath, path(jpPath, data)])
            .reduce((acc, [jpPath, data]) => assocPath(jpPath as string[], data, acc), {});
        result = this.excludeFields(result);
        if (Array.isArray(data)) {
            return values(result);
        }
        return result;
    }
    private excludeFields(data: any): any {
        const toExclude = this.attributes.filter(attribute => attribute.charAt(0) === '!');
        if (toExclude.length <= 0) {
            return data;
        }
        return toExclude
            .map(attribute => jp.paths(data, `$..${attribute.substr(1)}`))
            .reduce((a, b) => a.concat(b), [])
            .map(jpPath => jpPath.slice(1))
            .reduce((acc, jpPath) => dissocPath(jpPath, acc), data);
    }
}
