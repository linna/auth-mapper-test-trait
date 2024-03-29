<?php

/**
 * Linna Framework.
 *
 * @author Sebastian Rapetti <sebastian.rapetti@tim.it>
 * @copyright (c) 2020, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */
declare(strict_types=1);

namespace Linna\Authorization;

use Linna\Authentication\Password;
use Linna\DataMapper\NullDomainObject;
use Linna\DataMapper\Exception\NullDomainObjectException;
use Linna\Storage\ExtendedPDO;

/**
 * Permission Mapper Trait.
 */
trait PermissionMapperTrait
{
    /** @var ExtendedPDO Database connection. */
    protected static ExtendedPDO $pdo;

    /** @var PermissionMapper The permission mapper class. */
    protected static PermissionMapper $permissionMapper;

    /**
     * Test new instance.
     *
     * @return void
     */
    public function testNewInstance(): void
    {
        $this->assertInstanceOf(PermissionMapper::class, self::$permissionMapper);
    }

    /**
     * Permission id provider.
     *
     * @return array
     */
    public static function permissionIdProvider(): array
    {
        return [
            [1, 1],
            [2, 2],
            [3, 3],
            [4, 4],
            [5, 5],
            [6, 6],
            [7, 0],
            [8, 0]
        ];
    }

    /**
     * Test fetch by id.
     *
     * @dataProvider permissionIdProvider
     *
     * @param int $permissionId
     * @param int $expectedId
     *
     * @return void
     */
    public function testFetchById(int $permissionId, int $expectedId): void
    {
        $permission = self::$permissionMapper->fetchById($permissionId);

        if ($expectedId === 0) {
            $this->assertInstanceOf(NullDomainObject::class, $permission);
            $this->expectException(NullDomainObjectException::class);
        }

        $this->assertEquals($permission->getId(), $expectedId);
    }

    /**
     * Permission name provider
     *
     * @return array
     */
    public static function permissionNameProvider(): array
    {
        return [
            ['see users', 'see users'],
            ['update user', 'update user'],
            ['delete user', 'delete user'],
            ['create user', 'create user'],
            ['enable user', 'enable user'],
            ['disable user', 'disable user'],
            ['bad_permission_0', ''],
            ['bad_permission_1', '']
        ];
    }

    /**
     * Test fetch by name.
     *
     * @dataProvider permissionNameProvider
     *
     * @param string $permissionName
     * @param string $expectedName
     *
     * @return void
     */
    public function testFetchByName(string $permissionName, string $expectedName): void
    {
        $permission = self::$permissionMapper->fetchByName($permissionName);

        if ($expectedName === '') {
            $this->assertInstanceOf(NullDomainObject::class, $permission);
        }

        $this->assertEquals($permission->name, $expectedName);
    }

    /**
     * Test fetch all.
     *
     * @return void
     */
    public function testFetchAll(): void
    {
        $this->assertCount(6, self::$permissionMapper->fetchAll());
    }

    /**
     * Permission fetch limit provider.
     *
     * @return array
     */
    public static function permissionFetchLimitProvider(): array
    {
        return [
            ['create user', 0, 1],
            ['delete user', 1, 1],
            ['disable user', 2, 1],
            ['enable user', 3, 1],
            ['see users', 4, 1],
            ['update user', 5, 1]
        ];
    }

    /**
     * Test fetch limit.
     *
     * @dataProvider permissionFetchLimitProvider
     *
     * @param string $permissionName
     * @param int    $offset
     * @param int    $rowCount
     *
     * @return void
     */
    public function testFetchLimit(string $permissionName, int $offset, int $rowCount): void
    {
        $permissions = self::$permissionMapper->fetchLimit($offset, $rowCount);

        $key = \array_keys($permissions)[0];

        $this->assertCount(1, $permissions);
        $this->assertEquals($permissions[$key]->name, $permissionName);
    }

    /**
         * Role id provider.
         *
         * @return array
         */
    public static function roleIdProvider(): array
    {
        return [
            [1, 6],
            [2, 4],
            [3, 1],
            [4, 0],
            [5, 0]
        ];
    }

    /**
     * Test fetch by role.
     *
     * @dataProvider roleIdProvider
     *
     * @param int $roleId
     * @param int $result
     *
     * @return void
     */
    public function testFetchByRole(int $roleId, int $result): void
    {
        $this->assertCount($result, self::$permissionMapper->fetchByRole(new Role(id: $roleId)));
    }

    /**
     * Test fetch by role id.
     *
     * @dataProvider roleIdProvider
     *
     * @param int $roleId
     * @param int $result
     *
     * @return void
     */
    public function testFetchByRoleId(int $roleId, int $result): void
    {
        $this->assertCount($result, self::$permissionMapper->fetchByRoleId($roleId));
    }

    /**
     * Role name provider.
     *
     * @return array
     */
    public static function roleNameProvider(): array
    {
        return [
            ['Administrator', 6],
            ['Power Users', 4],
            ['Users', 1],
            ['unknown role 1', 0],
            ['unknown role 2', 0]
        ];
    }

    /**
     * Test fetch by role name.
     *
     * @dataProvider roleNameProvider
     *
     * @param string $roleName
     * @param int    $result
     *
     * @return void
     */
    public function testFetchByRoleName(string $roleName, int $result): void
    {
        $this->assertCount($result, self::$permissionMapper->fetchByRoleName($roleName));
    }

    /**
     * User id provider.
     *
     * @return array
     */
    public static function userIdProvider(): array
    {
        return [
            [1, 6],
            [2, 4],
            [3, 4],
            [4, 3],
            [5, 5],
            [6, 1],
            [7, 1],
            [8, 0],
            [9, 0]
        ];
    }

    /**
     * Test fetch by user.
     *
     * @dataProvider userIdProvider
     *
     * @param int $userId
     * @param int $result
     *
     * @return void
     */
    public function testFetchByUser(int $userId, int $result): void
    {
        $this->assertCount($result, self::$permissionMapper->fetchByUser(new User(passwordUtility: new Password(), id: $userId)));
    }

    /**
     * Test fetch by user id.
     *
     * @dataProvider userIdProvider
     *
     * @param int $userId
     * @param int $result
     *
     * @return void
     */
    public function testFetchByUserId(int $userId, int $result): void
    {
        $this->assertCount($result, self::$permissionMapper->fetchByUserId($userId));
    }

    /**
     * User name provider.
     *
     * @return array
     */
    public static function userNameProvider(): array
    {
        return [
            ['root', 6],
            ['User_0', 4],
            ['User_1', 4],
            ['User_2', 3],
            ['User_3', 5],
            ['User_4', 1],
            ['User_5', 1],
            ['unknown user 1', 0],
            ['unknown user 2', 0]
        ];
    }

    /**
     * Test fetch by user name.
     *
     * @dataProvider userNameProvider
     *
     * @param string $userName
     * @param int    $result
     *
     * @return void
     */
    public function testFetchByUserName(string $userName, int $result): void
    {
        $this->assertCount($result, self::$permissionMapper->fetchByUserName($userName));
    }

    /**
     * Test concrete create.
     *
     * @return void
     */
    public function testConcreteCreate(): void
    {
        $this->assertInstanceOf(Permission::class, self::$permissionMapper->create());
    }

    /**
     * Test concrete insert.
     *
     * @return void
     */
    public function testConcreteInsert(): void
    {
        //create permission
        $permission = self::$permissionMapper->create();
        $permission->name = 'test_permission';
        $permission->description = 'test_permission description';

        //check for clean permission
        $this->assertSame(null, $permission->getId());

        self::$permissionMapper->save($permission);

        //check if saved
        $this->assertGreaterThan(0, $permission->getId());

        //get one more time the permission
        $permissionStored = self::$permissionMapper->fetchByName('test_permission');

        //check
        $this->assertInstanceOf(Permission::class, $permissionStored);
        $this->assertSame($permission->id, $permissionStored->id);
        $this->assertSame($permission->name, $permissionStored->name);
        $this->assertSame($permission->description, $permissionStored->description);

        //clean
        self::$permissionMapper->delete($permissionStored);
    }

    /**
     * Test concrete update.
     *
     * @return void
     */
    public function testConcreteUpdate(): void
    {
        $permission = self::$permissionMapper->create();
        $permission->name = 'test_permission';
        $permission->description = 'test_permission description';

        self::$permissionMapper->save($permission);

        $permissionStored = self::$permissionMapper->fetchByName('test_permission');

        $this->assertInstanceOf(Permission::class, $permissionStored);

        $permissionStored->name = 'test_permission_update';
        $permissionStored->description = 'test_permission_update description';

        self::$permissionMapper->save($permissionStored);

        $permissionStoredUpdated = self::$permissionMapper->fetchByName('test_permission_update');

        $this->assertInstanceOf(Permission::class, $permissionStoredUpdated);
        $this->assertEquals($permissionStoredUpdated->name, $permissionStored->name);
        $this->assertEquals($permissionStoredUpdated->description, $permissionStored->description);

        //clean
        self::$permissionMapper->delete($permissionStored);
    }

    /**
     * Role id provider.
     *
     * @return array
     */
    /*public function roleIdProvider(): array
    {
        return [
            [1, 6],
            [2, 4],
            [3, 1],
            [4, 0]
        ];
    }

    /**
     * Test fetch by role.
     *
     * @dataProvider roleIdProvider
     *
     * @param int $roleId
     * @param int $result
     *
     * @return void
     */
    /*public function testFetchByRole(int $roleId, int $result): void
    {
        $role = self::$roleMapper->fetchById($roleId);

        if ($role instanceof Role) {
            $this->assertCount($result, self::$permissionMapper->fetchByRole($role));
        }

        if ($role instanceof NullDomainObject) {
            $this->assertSame($roleId, 4);
            $this->assertSame($result, 0);
        }
    }

    /**
     * Test fetch by role id.
     *
     * @dataProvider roleIdProvider
     *
     * @param int $roleId
     * @param int $result
     *
     * @return void
     */
    /*public function testFetchByRoleId(int $roleId, int $result): void
    {
        $this->assertCount($result, self::$permissionMapper->fetchByRoleId($roleId));
    }

    /**
     * Role name provider.
     *
     * @return array
     */
    /*public function roleNameProvider(): array
    {
        return [
            ['Administrator', 6],
            ['Power Users', 4],
            ['Users', 1],
            ['Other', 0]
        ];
    }

    /**
     * Test fetch by role name.
     *
     * @dataProvider roleNameProvider
     *
     * @param string $roleName
     * @param int    $result
     *
     * @return void
     */
    /*public function testFetchByRoleName(string $roleName, int $result): void
    {
        $this->assertCount($result, self::$permissionMapper->fetchByRoleName($roleName));
    }

    /**
     * User id provider.
     *
     * @return array
     */
    /*public function userIdProvider(): array
    {
        return [
            [1, 6],
            [2, 4],
            [3, 4],
            [4, 3],
            [5, 5],
            [6, 1],
            [7, 1],
            [8, 0]
        ];
    }

    /**
     * Test fetch by user.
     *
     * @dataProvider userIdProvider
     *
     * @param int $userId
     * @param int $result
     *
     * @return void
     */
    /*public function testFetchByUser(int $userId, int $result): void
    {
        $user = self::$enhancedUserMapper->fetchById($userId);

        if ($user instanceof EnhancedUser) {
            $this->assertCount($result, self::$permissionMapper->fetchByUser($user));
        }

        if ($user instanceof NullDomainObject) {
            $this->assertSame($userId, 8);
            $this->assertSame($result, 0);
        }
    }

    /**
     * Test fetch by user id.
     *
     * @dataProvider userIdProvider
     *
     * @param int $userId
     * @param int $result
     *
     * @return void
     */
    /*public function testFetchByUserId(int $userId, int $result): void
    {
        $this->assertCount($result, self::$permissionMapper->fetchByUserId($userId));
    }

    /**
     * User name provider.
     *
     * @return array
     */
    /*public function userNameProvider(): array
    {
        return [
            ['root', 6],
            ['User_0', 4],
            ['User_1', 4],
            ['User_2', 3],
            ['User_3', 5],
            ['User_4', 1],
            ['User_5', 1],
            ['other_user', 0]
        ];
    }

    /**
     * Test fetch by user name.
     *
     * @dataProvider userNameProvider
     *
     * @param string $userName
     * @param int    $result
     *
     * @return void
     */
    /*public function testFetchByUserName(string $userName, int $result): void
    {
        $this->assertCount($result, self::$permissionMapper->fetchByUserName($userName));
    }

    /**
     * Test fetch user permission hash table.
     *
     * @return void
     */
    /*public function testFetchUserPermissionHashTable(): void
    {
        $array = [
            '1a948f1b4374f4e3f02501c7feb43784021718a93c1ed5f9f19adf357bb2d20e' => 0,
            '77ac319bfe1979e2d799d9e6987e65feb54f61511c03552ebae990826c208590' => 1,
            '9c193c604ad7de942961af97b39ff541f2e611fdf0b93a3044e16dfbd808f41b' => 2,
            '9f29a130438b81170b92a42650f9a94291ecad60bd47af2a3886e75f7f728725' => 3,
            'b05e244762b1e472be89a93800cc3ee326743cecb55984bf12813addb8de66d0' => 4,
            'ec6c168f4411ec8fa9ab8d47dd25954ce53728404fed0e7a9bc7f29dab38c30d' => 5
        ];

        $this->assertEquals($array, self::$permissionMapper->fetchUserPermissionHashTable(1));

        //var_dump();

        //$this->assertTrue(true);
    }

    /**
     * Test permission exists by id.
     *
     * @dataProvider permissionIdProvider
     *
     * @param int  $permissionId
     * @param bool $result
     *
     * @return void
     */
    /*public function testPermissionExistById(int $permissionId, int $result): void
    {
        $this->assertSame((bool) $result, self::$permissionMapper->permissionExistById($permissionId));
    }

    /**
     * Test permission exists by name.
     *
     * @dataProvider permissionNameProvider
     *
     * @param string $permissionName
     * @param bool   $result
     *
     * @return void
     */
    /*public function testPermissionExistByName(string $permissionName, string $result): void
    {
        $this->assertSame((bool) $result, self::$permissionMapper->permissionExistByName($permissionName));
    }

    /**
     * Test concrete create.
     *
     * @return void
     */
    /*public function testConcreteCreate(): void
    {
        $this->assertInstanceOf(Permission::class, self::$permissionMapper->create());
    }

    /**
     * Test concrete insert.
     *
     * @return void
     */
    /*public function testConcreteInsert(): void
    {
        $permission = self::$permissionMapper->create();
        $permission->name = 'test_permission';

        $this->assertEquals(0, $permission->getId());

        self::$permissionMapper->save($permission);

        $this->assertGreaterThan(0, $permission->getId());

        $permissionStored = self::$permissionMapper->fetchByName('test_permission');

        $this->assertInstanceOf(Permission::class, $permissionStored);
    }

    /**
     * Test concrete update.
     *
     * @depends testConcreteInsert
     *
     * @return void
     */
    /*public function testConcreteUpdate(): void
    {
        $permissionStored = self::$permissionMapper->fetchByName('test_permission');

        $this->assertInstanceOf(Permission::class, $permissionStored);
        $this->assertEquals('test_permission', $permissionStored->name);

        $permissionStored->name = 'test_permission_update';

        self::$permissionMapper->save($permissionStored);

        $permissionStoredUpdated = self::$permissionMapper->fetchByName('test_permission_update');

        $this->assertInstanceOf(Permission::class, $permissionStoredUpdated);
        $this->assertEquals('test_permission_update', $permissionStoredUpdated->name);
    }

    /**
     * Test concrete delete.
     *
     * @depends testConcreteInsert
     *
     * @return void
     */
    /*public function testConcreteDelete(): void
    {
        $permissionStored = self::$permissionMapper->fetchByName('test_permission_update');

        $this->assertInstanceOf(Permission::class, $permissionStored);
        $this->assertEquals('test_permission_update', $permissionStored->name);

        self::$permissionMapper->delete($permissionStored);

        $this->assertInstanceOf(NullDomainObject::class, $permissionStored);
    }*/
}
