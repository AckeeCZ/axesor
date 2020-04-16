import { AccessControl } from 'accesscontrol';
import { flatten, toPairs, values } from 'ramda';
import { AclPermission } from './AclPermission';

interface AclOptions {
    getRoles(user: any): string[];
    logger?: any;
    ownerFunctions?: {
        [key: string]: (user: any, resource: any) => boolean;
    };
    inheritance?: Record<string, string[]>;
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
        if (options.inheritance) {
            this.addRoleInheritance(options.inheritance);
        }
    }
    public can(user: any): AclQuery {
        return values(Action).reduce(
            (acc, action) => {
                acc[action] = (resource: any, resourceType: string) => {
                    const customFunctions = this.customFunctions[action][resourceType];
                    if (customFunctions) {
                        return this.getPermission(customFunctions, {
                            action,
                            resource,
                            resourceType,
                            user,
                        });
                    }
                    return this.getGeneralPermission(action, user, resource, resourceType);
                };
                return acc;
            },
            {} as AclQuery
        );
    }
    public async addRule(actionInput: Action | '*', resourceType: string, rule: AddRule) {
        const actions = actionInput === '*' ? values(Action) : [actionInput];
        actions.forEach(action => {
            if (!this.customFunctions[action][resourceType]) {
                this.customFunctions[action][resourceType] = [];
            }
            this.customFunctions[action][resourceType].push(rule);
        });
    }
    public addRoleInheritance(inheritanceMap: Record<string, string[]>) {
        toPairs(inheritanceMap).map(([superRole, subRoles]) => this.ac.grant(superRole).extend(subRoles));
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
            attributes: attributes.includes('*')
                ? attributes.filter(attr => attr === '*' || attr.charAt(0) === '!')
                : attributes,
            action: params.action,
            granted: params.granted,
            resource: params.resourceType,
            roles: this.options.getRoles(user),
        });
    }
    private getGeneralPermission(action: Action, user: any, resource: any, resourceType: string) {
        const ownFn = `${action}Own` as 'createOwn' | 'deleteOwn' | 'readOwn' | 'updateOwn';
        const anyFn = `${action}Any` as 'createAny' | 'deleteAny' | 'readAny' | 'updateAny';
        const attributes = flatten(
            this.options.getRoles(user).map(role => {
                if (this.ownerFunctions[resourceType] && this.ownerFunctions[resourceType](user, resource)) {
                    return this.ac.can(role)[ownFn](resourceType).attributes;
                }
                return this.ac.can(role)[anyFn](resourceType).attributes;
            })
        );
        return this.createPermission(user, {
            action,
            resourceType,
            attributes: [...new Set(attributes)],
            granted: attributes.length > 0,
        });
    }
}

export default Acl;
