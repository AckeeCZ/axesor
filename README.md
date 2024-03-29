<div align="center">

## DEPRECATION NOTICE

This package is no longer maintained.
</div>

<div align="center">

[![Build Status](https://img.shields.io/travis/com/AckeeCZ/axesor/master.svg?style=flat-square)](https://travis-ci.com/AckeeCZ/axesor)
[![Coverage](https://img.shields.io/codeclimate/coverage/AckeeCZ/axesor.svg?style=flat-square)](https://codeclimate.com/github/AckeeCZ/axesor)
[![Maintainability](https://img.shields.io/codeclimate/maintainability/AckeeCZ/axesor.svg?style=flat-square)](https://codeclimate.com/github/AckeeCZ/axesor)
[![Vulnerabilities](https://img.shields.io/snyk/vulnerabilities/github/AckeeCZ/axesor.svg?style=flat-square)](https://snyk.io/test/github/AckeeCZ/axesor?targetFile=package.json)
[![Dependency Status](https://img.shields.io/david/AckeeCZ/axesor.svg?style=flat-square)](https://david-dm.org/AckeeCZ/axesor)
[![Dev Dependency Status](https://img.shields.io/david/dev/AckeeCZ/axesor.svg?style=flat-square)](https://david-dm.org/AckeeCZ/axesor?type=dev)

<img src="./resources/logo.png" height="170"/>
</div>

# Axesor

Axesor is tiny package for working with ACLs. Axesor using the [`accesscontrol`](https://github.com/onury/accesscontrol) package. 

GitHub repository: [https://github.com/AckeeCZ/axesor](https://github.com/AckeeCZ/axesor)

## Install

```bash
npm i --save axesor
```

## Usage

```typescript
import { Acl } from 'axesor';

// define all your grants
const grants = {
    admin: {
        video: {
            'create:any': ['*', '!views'],
            'read:any': ['*'],
            'update:any': ['*', '!views'],
            'delete:any': ['*']
        }
    },
    user: {
        video: {
            'create:own': ['*', '!rating', '!views'],
            'read:own': ['*'],
            'update:own': ['*', '!rating', '!views'],
            'delete:own': ['*']
        }
    }
};

// define options
const options = {
    getRoles: (user) => user.roles,     // required - return string[]
    logger: console,                    // optional
    ownerFunctions: {                   // optional - here you can specify ownership between resources
        video: (user, video) => user.id === video.userId,
    },
};

const ac = new Acl(grants, options);
// user = logged user
// .read(video, 'video')
//      - first argument is resource (for example row from database)
//      - second argument is string key - name of the resource you define in grants object
// returns
//      - granted: boolean      - if user is granted to read
//      - action: string        - read, create, update, delete
//      - roles: string[]       - user roles
//      - resource: string      - resource string key representation from grants object
//      - attributes: string[]  - JSON path string array of resource fields which user is allowed to read / update / create / delete - array of fields which you define in grants object
const permission = ac.can(user).read(video, 'video'); // .create(), .update(), .delete() with same arguments
// you can use filter function to filter fields from resource which user can manipulate with
// this function filters recursively
const allowedVideo = permission.filter(video);
```

### Custom rules

- You can define custom rules, these functions are called always when you are calling one of the `read` / `update` / `create` / `delete` functions
- Custom rules returns inside the `attributes` field only `[]` or `['*']` - not allowed or allowed with all grants
- Arguments:
    1) action           - `read` / `update` / `create` / `delete`
    2) resource type    - string resource key which you define in grants object
    3) custom function  - with logged user and resource object, it must return boolean or you can throw an error
- If rule is defined for some action and resource, the function will be called always when you call `ac.can(user).read(booking, 'bookings')` for example
- **Custom rules have greater importance then `ownerFunctions`, these functions will be called firstly**

```typescript
import { Acl, Action } from 'axesor';

const ac = new Acl({}, {}); // todo

ac.addRule(Action.update, 'bookings', (user, booking) => {
    if ((user.roles.includes('partner') && user.partnerId === booking.partnerId)
        || user.roles.includes('admin')) {
        return true;
    }
    throw new Error('You are not allowed to edit this booking');
});
ac.addRule(Action.update, 'bookings', (user, booking) => {
    if (booking.state === 'closed' && !user.roles.includes('admin')) {
        throw new Error('You are not allowed to edit closed booking');
    }
    return true;
});
```

### Role inheritance
Create a role hierarchy via inheritance.
```typescript
import { Acl, Action } from 'axesor';

const grants = {
    admin: {
        rocket: {
            'create:any': ['*'],
            'read:any': ['*'],
            'update:any': ['*'],
            'delete:any': ['*'],
        }
    },
    user: {
        bike: {
            'create:any': ['*'],
            'read:any': ['*'],
            'update:any': ['*'],
            'delete:any': ['*'],
        }
    }
};

const inheritance: {
    // admin extends user --> can manage rockets and bikes
    admin: 'user',
    // can also inherit multiple: admin: ['user']
}

const ac = new Acl(grants, { inheritance, // todo });
```

```typescript
// alternatively add via method
const ac = new Acl(grants, { // todo });
ac.addRoleInheritance(inheritance)
```

Make sure to reference only roles defined in grants object. For more info, see [roles](https://github.com/onury/accesscontrol#roles).

## Tests

```bash
npm run test
```

## License

This project is licensed under [MIT](./LICENSE).
