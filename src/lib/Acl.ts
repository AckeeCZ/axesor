import { AccessControl, Permission } from 'accesscontrol';
import { AclPermission } from './AclPermission';

interface AclOptions {
    getRoles(user: any): string[];
    logger?: any;
    ownerFunctions?: {
        [key: string]: (user: any, resource: any) => boolean;
    };
}

interface AclQuery {
    create(resource: any, type: string): Permission;
    delete(resource: any, type: string): Permission;
    read(resource: any, type: string): Permission;
    update(resource: any, type: string): Permission;
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
    user: any;
    resource: any;
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
                const role = this.options.getRoles(user)[0];
                const customFunctions = this.customFunctions[Action.create][resourceType];
                if (customFunctions) {
                    return this.getPermission(customFunctions, {
                        resource,
                        resourceType,
                        user,
                        action: Action.create,
                    });
                }
                if (this.ownerFunctions[resourceType] && this.ownerFunctions[resourceType](user, resource)) {
                    return this.ac.can(role).createOwn(resourceType);
                }
                return this.ac.can(role).createAny(resourceType);
            },
            delete: (resource: any, resourceType: string) => {
                const role = this.options.getRoles(user)[0];
                const customFunctions = this.customFunctions[Action.delete][resourceType];
                if (customFunctions) {
                    return this.getPermission(customFunctions, {
                        resource,
                        resourceType,
                        user,
                        action: Action.delete,
                    });
                }
                if (this.ownerFunctions[resourceType] && this.ownerFunctions[resourceType](user, resource)) {
                    return this.ac.can(role).deleteOwn(resourceType);
                }
                return this.ac.can(role).deleteAny(resourceType);
            },
            read: (resource: any, resourceType: string) => {
                const role = this.options.getRoles(user)[0];
                const customFunctions = this.customFunctions[Action.read][resourceType];
                if (customFunctions) {
                    return this.getPermission(customFunctions, {
                        resource,
                        resourceType,
                        user,
                        action: Action.read,
                    });
                }
                if (this.ownerFunctions[resourceType] && this.ownerFunctions[resourceType](user, resource)) {
                    return this.ac.can(role).readOwn(resourceType);
                }
                return this.ac.can(role).readAny(resourceType);
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
                const role = this.options.getRoles(user)[0];
                if (this.ownerFunctions[resourceType] && this.ownerFunctions[resourceType](user, resource)) {
                    return this.ac.can(role).updateOwn(resourceType);
                }
                return this.ac.can(role).updateAny(resourceType);
            },
        };
    }
    public async addRule(action: Action, resourceType: string, rule: AddRule) {
        this.customFunctions[action][resourceType].push(rule);
    }
    private getPermission(customFunctions: CustomRule[], options: PermissionOptions) {
        const result = customFunctions
            .map(async customFunction => await customFunction(options.user, options.resource))
            .filter(x => x);
        return new AclPermission({
            action: options.action,
            attributes: result.length > 0 ? ['*'] : [],
            granted: result.length > 0,
            resource: options.resourceType,
            roles: this.options.getRoles(options.user),
        });
    }
}
