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

enum Action {
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
            this.customFunctions[actionKey] = {} as CustomFunction;
        }
    }
    public can(user: object): AclQuery {
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
                let attributes = flatten(this.options.getRoles(user)
                    .map(role => {
                        if (this.ownerFunctions[resourceType] && this.ownerFunctions[resourceType](user, resource)) {
                            return this.ac.can(role).createOwn(resourceType).attributes;
                        }
                        return this.ac.can(role).createAny(resourceType).attributes;
                    })
                );
                attributes = [... new Set(attributes)];
                return this.createPermission(user, {
                    attributes,
                    resourceType,
                    action: Action.create,
                    granted: attributes.length > 0,
                });
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
                let attributes = flatten(this.options.getRoles(user)
                    .map(role => {
                        if (this.ownerFunctions[resourceType] && this.ownerFunctions[resourceType](user, resource)) {
                            return this.ac.can(role).createOwn(resourceType).attributes;
                        }
                        return this.ac.can(role).createAny(resourceType).attributes;
                    })
                );
                attributes = [... new Set(attributes)];
                return this.createPermission(user, {
                    attributes,
                    resourceType,
                    action: Action.create,
                    granted: attributes.length > 0,
                });
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
                let attributes = flatten(this.options.getRoles(user)
                    .map(role => {
                        if (this.ownerFunctions[resourceType] && this.ownerFunctions[resourceType](user, resource)) {
                            return this.ac.can(role).createOwn(resourceType).attributes;
                        }
                        return this.ac.can(role).createAny(resourceType).attributes;
                    })
                );
                attributes = [... new Set(attributes)];
                return this.createPermission(user, {
                    attributes,
                    resourceType,
                    action: Action.create,
                    granted: attributes.length > 0,
                });
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
                let attributes = flatten(this.options.getRoles(user)
                    .map(role => {
                        if (this.ownerFunctions[resourceType] && this.ownerFunctions[resourceType](user, resource)) {
                            return this.ac.can(role).createOwn(resourceType).attributes;
                        }
                        return this.ac.can(role).createAny(resourceType).attributes;
                    })
                );
                attributes = [... new Set(attributes)];
                return this.createPermission(user, {
                    attributes,
                    resourceType,
                    action: Action.create,
                    granted: attributes.length > 0,
                });
            },
        };
    }
    public async addRule(action: Action, resourceType: string, rule: AddRule) {
        this.customFunctions[action][resourceType].push(rule);
    }
    private getPermission(customFunctions: CustomRule[], options: { user: any, resource: any, action: Action, resourceType: string }) {
        const result = customFunctions
            .map(async customFunction => await customFunction(options.user, options.resource))
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
}
