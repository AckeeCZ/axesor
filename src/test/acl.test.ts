import { Acl, Action } from 'lib/Acl';
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
    test('Basic rule with filter', () => {
        const ac = new Acl(
            {
                user: {
                    books: {
                        'read:any': ['chapters.*.name'],
                    },
                },
            },
            { getRoles: user => user.roles }
        );
        const user = { id: 1, roles: ['user'] };
        const book = {
            id: 1,
            ownerId: 1,
            title: 'The Firm',
            author: 'John Grisham',
            chapters: [
                {
                    name: 'Mitchell McDeere',
                    pageStart: 1,
                    pages: 1,
                },
                {
                    name: 'Bendini, Lambert and Locke',
                    pageStart: 2,
                    pages: 2,
                },
            ],
        };

        const permission = ac.can(user).read(book, 'books');
        const allowedBook = permission.filter(book);
        expect(allowedBook).toEqual({
            chapters: [
                {
                    name: 'Mitchell McDeere',
                },
                {
                    name: 'Bendini, Lambert and Locke',
                },
            ],
        });
    });
    test('Basic rule with array filter', () => {
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
        const books = [
            {
                name: 'The Great Gatsby',
            },
            {
                name: 'The Firm',
            },
        ];

        const permission = ac.can(user).read(books, 'books');
        const allowedBook = permission.filter(books);
        expect(allowedBook).toEqual(books);
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
        expect(permission.attributes.sort()).toEqual(['*']);
        expect(allowedBook).toEqual(book);
    });
    test('Basic rule - nested object', () => {
        const ac = new Acl(
            {
                user: {
                    books: {
                        'create:any': ['title', 'author', 'address.id', 'pages.*.number'],
                    },
                },
            },
            {
                getRoles: user => user.roles,
            }
        );
        const user = { id: 1, roles: ['user'] };
        const bookPages = [{ id: 1, number: 64 }, { id: 2, number: 23 }];
        const book = {
            id: 1,
            ownerId: 1,
            title: 'The Firm',
            author: 'John Grisham',
            address: { id: 1, name: 'D Book' },
            pages: bookPages,
        };

        const permission = ac.can(user).create(book, 'books');
        const allowedBook = permission.filter(book);

        expect(permission.granted).toBe(true);
        expect(permission.attributes).toEqual(['title', 'author', 'address.id', 'pages.*.number']);
        expect(allowedBook).toEqual({
            title: book.title,
            author: book.author,
            address: { id: book.address.id },
            pages: bookPages.map(pick(['number'])),
        });
    });
    test('Simple custom rule', () => {
        const ac = new Acl(
            {
                user: {
                    bookings: {
                        'read:own': ['*'],
                    },
                },
            },
            {
                getRoles: (user: any) => user.roles,
            }
        );
        ac.addRule(Action.read, 'bookings', (user, booking) => {
            if (user.roles.includes('partner') && booking.partnerId === user.partnerId) {
                return true;
            }
            if (user.roles.includes('user') && booking.state !== 'canceled') {
                return true;
            }
            return user.roles.includes('admin');
        });
        const user = { id: 2, roles: ['user'], partnerId: null };
        const booking = {
            id: 1,
            userId: 2,
            partnerId: 3,
            state: 'new',
            description: 'Amazing description',
            createdAt: new Date('2019-03-01'),
        };
        const permission = ac.can(user).read(booking, 'bookings');
        const allowedBooking = permission.filter(booking);
        expect(permission.granted).toBe(true);
        expect(permission.attributes).toEqual(['*']);
        expect(allowedBooking).toEqual(booking);
    });
    test('Simple custom rule - failure', () => {
        const ac = new Acl(
            {
                partner: {
                    bookings: {
                        'read:own': ['*'],
                    },
                },
            },
            {
                getRoles: (user: any) => user.roles,
            }
        );
        ac.addRule(Action.read, 'bookings', (user, booking) => {
            if (user.roles.includes('partner') && booking.partnerId === user.partnerId) {
                return true;
            }
            if (user.roles.includes('user') && booking.state !== 'canceled') {
                return true;
            }
            return user.roles.includes('admin');
        });
        const user = { id: 1, roles: ['partner'], partnerId: 2 };
        const booking = {
            id: 1,
            userId: 2,
            partnerId: 3,
            state: 'new',
            description: 'Amazing description',
            createdAt: new Date('2019-03-01'),
        };
        const permission = ac.can(user).read(booking, 'bookings');
        const allowedBooking = permission.filter(booking);
        expect(permission.granted).toBe(false);
        expect(permission.attributes).toEqual([]);
        expect(allowedBooking).toEqual({});
    });
    test('Advanced custom rule', () => {
        const ac = new Acl(
            {
                partner: {
                    bookings: {
                        'read:own': ['*'],
                    },
                },
            },
            {
                getRoles: (user: any) => user.roles,
            }
        );
        ac.addRule(Action.update, 'bookings', (user, booking) => {
            if (
                (user.roles.includes('partner') && user.partnerId === booking.partnerId) ||
                user.roles.includes('admin')
            ) {
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
        const user = { id: 1, roles: ['partner'], partnerId: 3 };
        const booking = {
            id: 1,
            userId: 2,
            partnerId: 3,
            state: 'new',
            description: 'Amazing description',
            createdAt: new Date('2019-03-01'),
            updatedAt: null,
        };
        const permission = ac.can(user).update(booking, 'bookings');
        const allowedBooking = permission.filter(booking);
        expect(permission.granted).toBe(true);
        expect(permission.attributes).toEqual(['*']);
        expect(allowedBooking).toEqual(booking);
    });
    test('Advanced custom rule - failure', () => {
        const ac = new Acl(
            {
                partner: {
                    bookings: {
                        'read:own': ['*'],
                    },
                },
            },
            {
                getRoles: (user: any) => user.roles,
            }
        );
        ac.addRule(Action.update, 'bookings', (user, booking) => {
            if (
                (user.roles.includes('partner') && user.partnerId === booking.partnerId) ||
                user.roles.includes('admin')
            ) {
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
        const user = { id: 1, roles: ['partner'], partnerId: 4 };
        const booking = {
            id: 1,
            userId: 2,
            partnerId: 3,
            state: 'new',
            description: 'Amazing description',
            createdAt: new Date('2019-03-01'),
            updatedAt: null,
        };
        expect(() => ac.can(user).update(booking, 'bookings')).toThrow(Error);
    });
    test('Exclude fields', () => {
        const ac = new Acl(
            {
                user: {
                    book: {
                        'read:any': ['*', '!author'],
                    },
                },
            },
            {
                getRoles: (user: any) => user.roles,
            }
        );
        const user = { id: 1, roles: ['user'] };
        const book = { id: 1, name: 'Romeo & Juliet', author: 'William Shakespeare', type: 'ebook' };
        const permission = ac.can(user).read(book, 'book');
        const allowedBook = permission.filter(book);
        expect(permission.granted).toBe(true);
        expect(Object.keys(allowedBook).length).toEqual(3);
        expect(Object.keys(allowedBook)).toEqual(['id', 'name', 'type']);
    });
    test('Exclude path', () => {
        const ac = new Acl(
            {
                user: {
                    books: {
                        'read:any': ['*', '!pages.0.number'],
                    },
                },
            },
            {
                getRoles: (user: any) => user.roles,
            }
        );
        const user = { roles: ['user'] };
        const books = [
            {
                id: 1,
                name: 'Lorem',
                type: 'paper',
                pages: [{ number: 1, text: 'Lorem' }, { number: 2, text: 'Lorem Ipsum' }],
            },
        ];
        const permission = ac.can(user).read(books, 'books');
        const allowedBooks = permission.filter(books);
        expect(permission.granted).toBe(true);
        expect(Array.isArray(allowedBooks)).toBe(true);
        expect(allowedBooks).toHaveLength(1);
        const book = allowedBooks[0];
        expect(Object.keys(book)).toEqual(['id', 'name', 'type', 'pages']);
        expect(Array.isArray(book.pages)).toBe(true);
        expect(book.pages.length).toEqual(2);
        const firstPage = book.pages[0];
        expect(Object.keys(firstPage).length).toEqual(1);
        expect(Object.keys(firstPage)).toEqual(['text']);
        expect(Object.keys(book.pages[1])).toEqual(['number', 'text']);
    });
    test('Exclude more paths', () => {
        const ac = new Acl(
            {
                user: {
                    book: {
                        'read:any': ['*', '!pages.0.number', '!type'],
                    },
                },
            },
            {
                getRoles: (user: any) => user.roles,
            }
        );
        const user = { roles: ['user'] };
        const book = {
            id: 1,
            name: 'Lorem',
            type: 'paper',
            pages: [{ number: 1, text: 'Lorem' }, { number: 2, text: 'Lorem Ipsum' }],
        };
        const permission = ac.can(user).read(book, 'book');
        const allowedBook = permission.filter(book);
        expect(permission.granted).toBe(true);
        expect(Object.keys(allowedBook)).toEqual(['id', 'name', 'pages']);
        expect(Array.isArray(allowedBook.pages)).toBe(true);
        expect(allowedBook.pages.length).toEqual(2);
        const firstPage = allowedBook.pages[0];
        expect(Object.keys(firstPage).length).toEqual(1);
        expect(Object.keys(firstPage)).toEqual(['text']);
        expect(Object.keys(allowedBook.pages[1])).toEqual(['number', 'text']);
    });
    test('Filter out unnecessary permission attributes', () => {
        const user = { roles: ['user'] };
        const book = {
            id: 1,
            name: 'Lorem',
            type: 'paper',
            pages: [{ number: 1, text: 'Lorem' }, { number: 2, text: 'Lorem Ipsum' }],
        };
        const acl = new Acl(
            {
                user: {
                    book: {
                        'read:any': ['*', '*', 'pages', 'pages', 'type', 'chapters', '!authors'],
                    },
                },
            },
            {
                getRoles: (user: any) => user.roles,
            }
        );
        const permission = acl.can(user).read(book, 'book');
        expect(permission.attributes.sort()).toEqual(['*', '!authors'].sort());
    });
});
