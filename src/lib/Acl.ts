
import { AccessControl, Permission } from 'accesscontrol';
import { AclPermission } from './AclPermission';

interface AclOptions {
    getRoles(user: any): string[];
    logger?: any;
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
    private ownerFunctions: OwnerFunctions = {};
    private customFunctions: CustomFunctions = {} as CustomFunctions;
    private ac: AccessControl;
    constructor(private grantsObject: any, private options: AclOptions) {
        this.ac = new AccessControl(grantsObject);
        this.logger = options.logger || console;
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
                    const result = customFunctions
                        .map(async customFunction => await customFunction(user, resource))
                        .filter(x => x);
                    return new AclPermission({
                        action: Action.create,
                        attributes: result.length > 0 ? ['*'] : [],
                        granted: result.length > 0,
                        resource: resourceType,
                        roles: [role],
                    });
                }
                if (this.ownerFunctions[resourceType] && this.ownerFunctions[resourceType](user, resource)) {
                    return this.ac.can(role).createOwn(resourceType);
                }
                return this.ac.can(role).createAny(resourceType);
            },
            delete: (resource: any, resourceType: string) => {
                const role = this.options.getRoles(user)[0];
                if (this.ownerFunctions[resourceType] && this.ownerFunctions[resourceType](user, resource)) {
                    return this.ac.can(role).deleteOwn(resourceType);
                }
                return this.ac.can(role).deleteAny(resourceType);
            },
            read: (resource: any, resourceType: string) => {
                const role = this.options.getRoles(user)[0];
                if (this.ownerFunctions[resourceType] && this.ownerFunctions[resourceType](user, resource)) {
                    return this.ac.can(role).readOwn(resourceType);
                }
                return this.ac.can(role).readAny(resourceType);
            },
            update: (resource: any, resourceType: string) => {
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
}
