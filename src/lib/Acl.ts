import { AccessControl, Permission } from 'accesscontrol';

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

type AddRule = (user: any, resource: any) => boolean;
type IsOwner = (user: any, resource: any) => boolean;

enum Action {
    create = 'create',
    delete = 'delete',
    read = 'read',
    update = 'update'
}

export class Acl {
    private logger: any;
    private ownerFunctions: OwnerFunctions = {};
    private ac: AccessControl;
    constructor(private grantsObject: any, private options: AclOptions) {
        this.ac = new AccessControl(grantsObject);
        this.logger = options.logger || console;
    }
    public can(user: object): AclQuery {
        return {
            create: (resource: any, resourceType: string) => {
                const role = this.options.getRoles(user)[0];
                if (this.ownerFunctions[resourceType](user, resource)) {
                    return this.ac.can(role).createOwn(resourceType);
                }
                return this.ac.can(role).createAny(resourceType);
            },
            delete: (resource: any, resourceType: string) => {
                const role = this.options.getRoles(user)[0];
                if (this.ownerFunctions[resourceType](user, resource)) {
                    return this.ac.can(role).deleteOwn(resourceType);
                }
                return this.ac.can(role).deleteAny(resourceType);
            },
            read: (resource: any, resourceType: string) => {
                const role = this.options.getRoles(user)[0];
                if (this.ownerFunctions[resourceType](user, resource)) {
                    return this.ac.can(role).readOwn(resourceType);
                }
                return this.ac.can(role).readAny(resourceType);
            },
            update: (resource: any, resourceType: string) => {
                const role = this.options.getRoles(user)[0];
                if (this.ownerFunctions[resourceType](user, resource)) {
                    return this.ac.can(role).updateOwn(resourceType);
                }
                return this.ac.can(role).updateAny(resourceType);
            },
        };
    }
    public addRule(action: Action, resourceType: string, rule: AddRule) {
        // todo
    }
}
