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
 * Role Mapper Trait.
 */
trait RoleMapperTrait
{
    /** @var ExtendedPDO Database connection. */
    protected static ExtendedPDO $pdo;

    /** @var RoleMapper The role mapper class. */
    protected static RoleMapper $roleMapper;

    /**
     * Test new instance.
     */
    public function testNewInstance(): void
    {
        $this->assertInstanceOf(RoleMapper::class, self::$roleMapper);
    }

    /**
     * Permission id provider.
     *
     * @return array
     */
    public static function roleIdProvider(): array
    {
        return [
            [1, 1],
            [2, 2],
            [3, 3],
            [4, 0],
            [5, 0]
        ];
    }

    /**
     * Test fetch by id.
     *
     * @dataProvider roleIdProvider
     *
     * @param int $roleId
     * @param int $expectedId
     *
     * @return void
     */
    public function testFetchById(int $roleId, int $expectedId): void
    {
        $role = self::$roleMapper->fetchById($roleId);

        if ($expectedId === 0) {
            $this->assertInstanceOf(NullDomainObject::class, $role);
            $this->expectException(NullDomainObjectException::class);
        }

        $this->assertEquals($role->getId(), $expectedId);
    }

    /**
     * Role name provider
     *
     * @return array
     */
    public static function roleNameProvider(): array
    {
        return [
            ['Administrator', 'Administrator'],
            ['Power Users', 'Power Users'],
            ['Users', 'Users'],
            ['bad_name_1', ''],
            ['bad_name_2', '']
        ];
    }

    /**
     * Test fetch by name.
     *
     * @dataProvider roleNameProvider
     *
     * @param string $roleName
     * @param string $expectedName
     *
     * @return void
     */
    public function testFetchByName(string $roleName, string $expectedName): void
    {
        $role = self::$roleMapper->fetchByName($roleName);

        if ($expectedName === '') {
            $this->assertInstanceOf(NullDomainObject::class, $role);
        }

        $this->assertEquals($role->name, $expectedName);
    }

    /**
     * Test fetch all.
     *
     * @return void
     */
    public function testFetchAll(): void
    {
        $this->assertCount(3, self::$roleMapper->fetchAll());
    }

    /**
     * Role fetch limit provider.
     *
     * @return array
     */
    public static function roleFetchLimitProvider(): array
    {
        return [
            ['Administrator', 0, 1],
            ['Power Users', 1, 1],
            ['Users', 2, 1]
        ];
    }

    /**
     * Test fetch limit.
     *
     * @dataProvider roleFetchLimitProvider
     *
     * @param string $roleName
     * @param int    $offset
     * @param int    $rowCount
     *
     * @return void
     */
    public function testFetchLimit(string $roleName, int $offset, int $rowCount): void
    {
        $role = self::$roleMapper->fetchLimit($offset, $rowCount);

        $key = \array_keys($role)[0];

        $this->assertCount(1, $role);
        $this->assertEquals($role[$key]->name, $roleName);
    }

    /**
     * Permission id provider.
     *
     * @return array
     */
    public static function permissionIdProvider(): array
    {
        return [
            [1, 3],
            [2, 2],
            [3, 1],
            [4, 1],
            [5, 2],
            [6, 2],
            [7, 0],
            [8, 0],
            [9, 0]
        ];
    }

    /**
     * Test fetch by permission.
     *
     * @dataProvider permissionIdProvider
     *
     * @param int $permissionId
     * @param int $result
     *
     * @return void
     */
    public function testFetchByPermission(int $permissionId, int $result): void
    {
        $this->assertCount($result, self::$roleMapper->fetchByPermission(new Permission(id:$permissionId)));
    }

    /**
     * Test fetch by permission id.
     *
     * @dataProvider permissionIdProvider
     *
     * @param int $permissionId
     * @param int $result
     *
     * @return void
     */
    public function testFetchByPermissionId(int $permissionId, int $result): void
    {
        $this->assertCount($result, self::$roleMapper->fetchByPermissionId($permissionId));
    }

    /**
     * Permission name provider.
     *
     * @return array
     */
    public static function permissionNameProvider(): array
    {
        return [
            ['see users', 3],
            ['update user', 2],
            ['delete user', 1],
            ['create user', 1],
            ['enable user', 2],
            ['disable user', 2],
            ['unknown permission 1', 0],
            ['unknown permission 2', 0]
        ];
    }

    /**
     * Test fetch by permission name.
     *
     * @dataProvider permissionNameProvider
     *
     * @param string $permissionName
     * @param int    $result
     *
     * @return void
     */
    public function testFetchByPermissionName(string $permissionName, int $result): void
    {
        $this->assertCount($result, self::$roleMapper->fetchByPermissionName($permissionName));
    }

    /**
     * User id provider.
     *
     * @return array
     */
    public static function userIdProvider(): array
    {
        return [
            [1, 1],
            [2, 1],
            [3, 1],
            [4, 1],
            [5, 1],
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
        $this->assertCount($result, self::$roleMapper->fetchByUser(new User(passwordUtility: new Password(), id: $userId)));
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
        $this->assertCount($result, self::$roleMapper->fetchByUserId($userId));
    }

    /**
     * User name provider.
     *
     * @return array
     */
    public static function userNameProvider(): array
    {
        return [
            ['root', 1],
            ['User_0', 1],
            ['User_1', 1],
            ['User_2', 1],
            ['User_3', 1],
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
        $this->assertCount($result, self::$roleMapper->fetchByUserName($userName));
    }

    /**
     * Test concrete create.
     *
     * @return void
     */
    public function testConcreteCreate(): void
    {
        $this->assertInstanceOf(Role::class, self::$roleMapper->create());
    }


    /**
     * Test concrete insert.
     *
     * @return void
     */
    public function testConcreteInsert(): void
    {
        //create role
        $role = self::$roleMapper->create();
        $role->name = 'test_role';
        $role->description = 'test_role description';
        $role->active = 1;

        //check for clean role
        $this->assertSame(null, $role->getId());

        self::$roleMapper->save($role);

        //check if saved
        $this->assertGreaterThan(0, $role->getId());

        //get one more time the role
        $roleStored = self::$roleMapper->fetchByName('test_role');

        //check
        $this->assertInstanceOf(Role::class, $roleStored);
        $this->assertSame($role->id, $roleStored->id);
        $this->assertSame($role->name, $role->name);
        $this->assertSame($role->description, $role->description);
        $this->assertSame($role->active, $role->active);

        //clean
        self::$roleMapper->delete($roleStored);
    }

    /**
     * Test concrete update.
     *
     * @return void
     */
    public function testConcreteUpdate(): void
    {
        $role = self::$roleMapper->create();
        $role->name = 'test_role';
        $role->description = 'test_role description';
        $role->active = 1;

        self::$roleMapper->save($role);

        $roleStored = self::$roleMapper->fetchByName('test_role');

        $this->assertInstanceOf(Role::class, $roleStored);

        $roleStored->name = 'test_role_update';
        $roleStored->description = 'test_role_update description';
        $roleStored->active = 0;

        self::$roleMapper->save($roleStored);

        $roleStoredUpdated = self::$roleMapper->fetchByName('test_role_update');

        $this->assertInstanceOf(Role::class, $roleStoredUpdated);
        $this->assertEquals($roleStoredUpdated->name, $roleStored->name);
        $this->assertEquals($roleStoredUpdated->description, $roleStored->description);
        $this->assertEquals($roleStoredUpdated->active, $roleStored->active);

        //clean
        self::$roleMapper->delete($roleStored);
    }
}
