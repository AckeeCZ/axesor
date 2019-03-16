import { Acl } from 'lib/Acl';
import { pick } from 'ramda';

describe('ACL', () => {
    test('Create AC object', () => {
        const ac = new Acl({}, { getRoles: user => user.roles });

        expect(ac).toBeDefined();
    });
    test('Basic rule', () => {
        const ac = new Acl(
            {
                user: {
                    books: {
                        'read:any': ['*'],
                    },
                },
            },
            { getRoles: user => user.roles }
        );
        const user = { id: 1, roles: ['user'] };
        const book = { id: 1, ownerId: 1, title: 'The Firm', author: 'John Grisham' };

        const permission = ac.can(user).read(book, 'books');
        const allowedBook = permission.filter(book);

        expect(permission.granted).toBe(true);
        expect(permission.attributes).toEqual(['*']);
        expect(allowedBook).toEqual(book);
    });
    test('Basic rule - own', () => {
        const ac = new Acl(
            {
                user: {
                    books: {
                        'read:own': ['*'],
                    },
                },
            },
            { getRoles: user => user.roles }
        );
        const user = { id: 1, roles: ['user'] };
        const book = { id: 1, ownerId: 1, title: 'The Firm', author: 'John Grisham' };

        const permission = ac.can(user).read(book, 'books');
        const allowedBook = permission.filter(book);

        expect(permission.granted).toBe(false);
        expect(permission.attributes).toEqual([]);
        expect(allowedBook).toEqual({});
    });
    test('Basic rule - own with owner', () => {
        const ac = new Acl(
            {
                user: {
                    books: {
                        'create:own': ['*'],
                    },
                },
            },
            {
                getRoles: user => user.roles,
                ownerFunctions: {
                    books: (user, book) => book.ownerId === user.id,
                },
            }
        );
        const user = { id: 1, roles: ['user'] };
        const book = { id: 1, ownerId: 1, title: 'The Firm', author: 'John Grisham' };

        const permission = ac.can(user).create(book, 'books');
        const allowedBook = permission.filter(book);
        expect(permission.granted).toBe(true);
        expect(permission.attributes).toEqual(['*']);
        expect(allowedBook).toEqual(book);
    });
    test('Basic rule - multiple roles', () => {
        const ac = new Acl(
            {
                user: {
                    books: {
                        'create:any': ['title', 'author'],
                    },
                },
                admin: {
                    books: {
                        'create:any': ['id'],
                    },
                },
            },
            {
                getRoles: user => user.roles,
            }
        );
        const user = { id: 1, roles: ['user', 'admin'] };
        const book = { id: 1, ownerId: 1, title: 'The Firm', author: 'John Grisham' };

        const permission = ac.can(user).create(book, 'books');
        const allowedBook = permission.filter(book);

        expect(permission.granted).toBe(true);
        expect(permission.attributes).toEqual(['title', 'author', 'id']);
        expect(allowedBook).toEqual(pick(['title', 'author', 'id'], book));
    });
    test('Basic rule - multiple roles asterisk', () => {
        const ac = new Acl(
            {
                user: {
                    books: {
                        'create:any': ['title', 'author'],
                    },
                },
                admin: {
                    books: {
                        'create:any': ['*'],
                    },
                },
            },
            {
                getRoles: user => user.roles,
            }
        );
        const user = { id: 1, roles: ['user', 'admin'] };
        const book = { id: 1, ownerId: 1, title: 'The Firm', author: 'John Grisham' };

        const permission = ac.can(user).create(book, 'books');
        const allowedBook = permission.filter(book);

        expect(permission.granted).toBe(true);
        expect(permission.attributes).toEqual(['*']);
        expect(allowedBook).toBe(book);
    });
});
