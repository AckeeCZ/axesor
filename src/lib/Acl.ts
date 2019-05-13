import { AccessControl } from 'accesscontrol';
import { flatten } from 'ramda';
import { AclPermission } from './AclPermission';

interface AclOptions {
    getRoles(user: any): string[];
    logger?: any;
    ownerFunctions?: {
        [key: string]: (user: any, resource: any) => boolean;
    };
}

interface AclQuery {
    create(resource: any, type: string): AclPermission;
    delete(resource: any, type: string): AclPermission;
    read(resource: any, type: string): AclPermission;
    update(resource: any, type: string): AclPermission;
}

interface OwnerFunctions {
    [index: string]: IsOwner;
}

interface CustomFunctions {
    [index: string]: CustomFunction;
}

interface CustomFunction {
    [index: string]: CustomRule[];
}

interface PermissionOptions {
    action: Action;
    attributes: string[];
    granted: boolean;
    resourceType: string;
}

type AddRule = (user: any, resource: any) => boolean;
type IsOwner = (user: any, resource: any) => boolean;
type CustomRule = (user: any, resource: any) => boolean;

export enum Action {
    create = 'create',
    delete = 'delete',
    read = 'read',
    update = 'update',
}

export class Acl {
    private logger: any;
    private readonly ownerFunctions: OwnerFunctions = {};
    private customFunctions: CustomFunctions = {};
    private ac: AccessControl;
    constructor(private grantsObject: any, private options: AclOptions) {
        this.ac = new AccessControl(grantsObject);
        this.logger = options.logger || console;
        this.ownerFunctions = options.ownerFunctions || {};
        for (const actionKey in Action) {
            this.customFunctions[actionKey] = {};
        }
    }
    public can(user: any): AclQuery {
        return {
            create: (resource: any, resourceType: string) => {
                const customFunctions = this.customFunctions[Action.create][resourceType];
                if (customFunctions) {
                    return this.getPermission(customFunctions, {
                        resource,
                        resourceType,
                        user,
                        action: Action.create,
                    });
                }
                return this.getCreatePermission(user, resource, resourceType);
            },
            delete: (resource: any, resourceType: string) => {
                const customFunctions = this.customFunctions[Action.delete][resourceType];
                if (customFunctions) {
                    return this.getPermission(customFunctions, {
                        resource,
                        resourceType,
                        user,
                        action: Action.delete,
                    });
                }
                return this.getDeletePermission(user, resource, resourceType);
            },
            read: (resource: any, resourceType: string) => {
                const customFunctions = this.customFunctions[Action.read][resourceType];
                if (customFunctions) {
                    return this.getPermission(customFunctions, {
                        resource,
                        resourceType,
                        user,
                        action: Action.read,
                    });
                }
                return this.getReadPermission(user, resource, resourceType);
            },
            update: (resource: any, resourceType: string) => {
                const customFunctions = this.customFunctions[Action.update][resourceType];
                if (customFunctions) {
                    return this.getPermission(customFunctions, {
                        resource,
                        resourceType,
                        user,
                        action: Action.update,
                    });
                }
                return this.getUpdatePermission(user, resource, resourceType);
            },
        };
    }
    public async addRule(action: Action, resourceType: string, rule: AddRule) {
        if (!this.customFunctions[action][resourceType]) {
            this.customFunctions[action][resourceType] = [];
        }
        this.customFunctions[action][resourceType].push(rule);
    }
    private getPermission(
        customFunctions: CustomRule[],
        options: { user: any; resource: any; action: Action; resourceType: string }
    ) {
        const result = customFunctions
            .map(customFunction => customFunction(options.user, options.resource))
            .filter(x => x);
        return this.createPermission(options.user, {
            action: options.action,
            attributes: result.length > 0 ? ['*'] : [],
            granted: result.length > 0,
            resourceType: options.resourceType,
        });
    }
    private createPermission(user: any, params: PermissionOptions) {
        const attributes = params.attributes;
        return new AclPermission({
            action: params.action,
            attributes: !attributes.includes('*') ? attributes : ['*'],
            granted: params.granted,
            resource: params.resourceType,
            roles: this.options.getRoles(user),
        });
    }
    private getCreatePermission(user: any, resource: any, resourceType: string) {
        const attributes = flatten(
            this.options.getRoles(user).map(role => {
                if (this.ownerFunctions[resourceType] && this.ownerFunctions[resourceType](user, resource)) {
                    return this.ac.can(role).createOwn(resourceType).attributes;
                }
                return this.ac.can(role).createAny(resourceType).attributes;
            })
        );
        return this.createPermission(user, {
            resourceType,
            attributes: [...new Set(attributes)],
            action: Action.create,
            granted: attributes.length > 0,
        });
    }
    private getDeletePermission(user: any, resource: any, resourceType: string) {
        const attributes = flatten(
            this.options.getRoles(user).map(role => {
                if (this.ownerFunctions[resourceType] && this.ownerFunctions[resourceType](user, resource)) {
                    return this.ac.can(role).deleteOwn(resourceType).attributes;
                }
                return this.ac.can(role).deleteAny(resourceType).attributes;
            })
        );
        return this.createPermission(user, {
            resourceType,
            attributes: [...new Set(attributes)],
            action: Action.delete,
            granted: attributes.length > 0,
        });
    }
    private getReadPermission(user: any, resource: any, resourceType: string) {
        const attributes = flatten(
            this.options.getRoles(user).map(role => {
                if (this.ownerFunctions[resourceType] && this.ownerFunctions[resourceType](user, resource)) {
                    return this.ac.can(role).readOwn(resourceType).attributes;
                }
                return this.ac.can(role).readAny(resourceType).attributes;
            })
        );
        return this.createPermission(user, {
            resourceType,
            attributes: [...new Set(attributes)],
            action: Action.read,
            granted: attributes.length > 0,
        });
    }
    private getUpdatePermission(user: any, resource: any, resourceType: string) {
        const attributes = flatten(
            this.options.getRoles(user).map(role => {
                if (this.ownerFunctions[resourceType] && this.ownerFunctions[resourceType](user, resource)) {
                    return this.ac.can(role).updateOwn(resourceType).attributes;
                }
                return this.ac.can(role).updateAny(resourceType).attributes;
            })
        );
        return this.createPermission(user, {
            resourceType,
            attributes: [...new Set(attributes)],
            action: Action.update,
            granted: attributes.length > 0,
        });
    }
}

export default Acl;
