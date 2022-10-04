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

use Linna\DataMapper\NullDomainObject;
use Linna\Storage\ExtendedPDO;

/**
 * Enhanced User Mapper Trait.
 */
trait EnhancedUserMapperTrait
{
    /** @var EnhancedUserMapper The enhanced user mapper class. */
    protected static EnhancedUserMapper $enhancedUserMapper;

    /** @var PermissionMapper The permission mapper class. */
    protected static PermissionMapper $permissionMapper;

    /** @var RoleMapper The role mapper class. */
    protected static RoleMapper $roleMapper;

    /** @var ExtendedPDO Database connection. */
    protected static ExtendedPDO $pdo;

    /**
     * Test new instance.
     */
    public function testNewInstance()
    {
        $this->assertInstanceOf(EnhancedUserMapper::class, self::$enhancedUserMapper);
    }

    /**
     * User id provider
     *
     * @return array
     */
    public function userIdProvider(): array
    {
        return [
            [1, 1],
            [2, 2],
            [3, 3],
            [4, 4],
            [5, 5],
            [6, 6],
            [7, 7],
            [8, 0]
        ];
    }

    /**
     * Test fetch by id.
     *
     * @dataProvider userIdProvider
     *
     * @param int $userId
     * @param int $expectedId
     *
     * @return void
     */
    public function testFetchById(int $userId, int $expectedId): void
    {
        $enhancedUser = self::$enhancedUserMapper->fetchById($userId);
        $this->assertEquals($enhancedUser->getId(), $expectedId);
    }

    /**
     * User name provider
     *
     * @return array
     */
    public function userNameProvider(): array
    {
        return [
            ['root', 'root'],
            ['User_0', 'User_0'],
            ['User_1', 'User_1'],
            ['User_2', 'User_2'],
            ['User_3', 'User_3'],
            ['User_4', 'User_4'],
            ['User_5', 'User_5'],
            ['bad_user', '']
        ];
    }

    /**
     * Test fetch by name.
     *
     * @dataProvider userNameProvider
     *
     * @param string $userName
     * @param string $expectedName
     *
     * @return void
     */
    public function testFetchByName(string $userName, string $expectedName): void
    {
        $enhancedUser = self::$enhancedUserMapper->fetchByName($userName);

        if ($expectedName === '') {
            $this->assertInstanceOf(NullDomainObject::class, $enhancedUser);
            return;
        }

        $this->assertEquals($enhancedUser->name, $expectedName);
    }

    /**
     * Test fetch all.
     *
     * @return void
     */
    public function testFetchAll(): void
    {
        $this->assertCount(7, self::$enhancedUserMapper->fetchAll());
    }

    /**
     * User fetch limit provider.
     *
     * @return array
     */
    public function userFetchLimitProvider(): array
    {
        return [
            ['root', 0, 1],
            ['User_0', 1, 1],
            ['User_1', 2, 1],
            ['User_2', 3, 1],
            ['User_3', 4, 1],
            ['User_4', 5, 1],
            ['User_5', 6, 1],
        ];
    }

    /**
     * Test fetch limit.
     *
     * @dataProvider userFetchLimitProvider
     *
     * @param string $userName
     * @param int    $offset
     * @param int    $rowCount
     *
     * @return void
     */
    public function testFetchLimit(string $userName, int $offset, int $rowCount): void
    {
        $enhancedUsers = self::$enhancedUserMapper->fetchLimit($offset, $rowCount);

        $key = \array_keys($enhancedUsers)[0];

        $this->assertCount(1, $enhancedUsers);
        $this->assertEquals($enhancedUsers[$key]->name, $userName);
    }

    /**
     * Permission id provider.
     *
     * @return array
     */
    public function permissionIdProvider(): array
    {
        return [
            [1, 7],
            [2, 3],
            [3, 2],
            [4, 2],
            [5, 5],
            [6, 5],
            [7, 0]
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
        $permission = self::$permissionMapper->fetchById($permissionId);

        if ($permission instanceof Permission) {
            $this->assertCount($result, self::$enhancedUserMapper->fetchByPermission($permission));
        }

        if ($permission instanceof NullDomainObject) {
            $this->assertSame($permissionId, 7);
            $this->assertSame($result, 0);
        }
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
        $this->assertCount($result, self::$enhancedUserMapper->fetchByPermissionId($permissionId));
    }

    /**
     * Permission name provider.
     *
     * @return array
     */
    public function permissionNameProvider(): array
    {
        return [
            ['see users', 7],
            ['update user', 3],
            ['delete user', 2],
            ['create user', 2],
            ['enable user', 5],
            ['disable user', 5],
            ['unknown permission', 0]
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
        $this->assertCount($result, self::$enhancedUserMapper->fetchByPermissionName($permissionName));
    }

    /**
     * Role id provider.
     *
     * @return array
     */
    public function roleIdProvider(): array
    {
        return [
            [1, 1],
            [2, 2],
            [3, 4],
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
    public function testFetchByRole(int $roleId, int $result): void
    {
        $role = self::$roleMapper->fetchById($roleId);

        if ($role instanceof Role) {
            $this->assertCount($result, self::$enhancedUserMapper->fetchByRole($role));
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
    public function testFetchByRoleId(int $roleId, int $result): void
    {
        $this->assertCount($result, self::$enhancedUserMapper->fetchByRoleId($roleId));
    }

    /**
     * Role name provider.
     *
     * @return array
     */
    public function roleNameProvider(): array
    {
        return [
            ['Administrator', 1],
            ['Power Users', 2],
            ['Users', 4],
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
    public function testFetchByRoleName(string $roleName, int $result): void
    {
        $this->assertCount($result, self::$enhancedUserMapper->fetchByRoleName($roleName));
    }

    /**
     * Test grant permission.
     *
     * @return void
     */
    public function testGrantPermission(): void
    {
        $user = self::$enhancedUserMapper->fetchById(7);
        $permission = self::$permissionMapper->fetchById(6);

        $this->assertInstanceOf(EnhancedUser::class, $user);
        $this->assertInstanceOf(Permission::class, $permission);

        self::$enhancedUserMapper->grantPermission($user, $permission);

        $this->assertTrue($user->can($permission));

        self::$enhancedUserMapper->revokePermission($user, $permission);

        $this->assertFalse($user->can($permission));
    }

    /**
     * Test grant permission by id.
     *
     * @return void
     */
    public function testGrantPermissionById(): void
    {
        $user = self::$enhancedUserMapper->fetchById(7);
        $permission = self::$permissionMapper->fetchById(6);

        $this->assertInstanceOf(EnhancedUser::class, $user);
        $this->assertInstanceOf(Permission::class, $permission);

        self::$enhancedUserMapper->grantPermissionById($user, $permission->id);

        $this->assertTrue($user->canById($permission->id));

        self::$enhancedUserMapper->revokePermissionById($user, $permission->id);

        $this->assertFalse($user->canById($permission->id));
    }

    /**
     * Test grant permission by name.
     *
     * @return void
     */
    public function testGrantPermissionByName(): void
    {
        $user = self::$enhancedUserMapper->fetchById(7);
        $permission = self::$permissionMapper->fetchById(6);

        $this->assertInstanceOf(EnhancedUser::class, $user);
        $this->assertInstanceOf(Permission::class, $permission);

        self::$enhancedUserMapper->grantPermissionByName($user, $permission->name);

        $this->assertTrue($user->canByName($permission->name));

        self::$enhancedUserMapper->revokePermissionByName($user, $permission->name);

        $this->assertFalse($user->canByName($permission->name));
    }

    /**
     * Test revoke permission.
     *
     * @return void
     */
    public function testRevokePermission(): void
    {
        $user = self::$enhancedUserMapper->fetchById(7);
        $permission = self::$permissionMapper->fetchById(6);

        $this->assertInstanceOf(EnhancedUser::class, $user);
        $this->assertInstanceOf(Permission::class, $permission);

        $this->assertFalse($user->can($permission));

        self::$enhancedUserMapper->grantPermission($user, $permission);

        $this->assertTrue($user->can($permission));

        self::$enhancedUserMapper->revokePermission($user, $permission);

        $this->assertFalse($user->can($permission));
    }

    /**
     * Test revoke permission by id.
     *
     * @return void
     */
    public function testRevokePermissionById(): void
    {
        $user = self::$enhancedUserMapper->fetchById(7);
        $permission = self::$permissionMapper->fetchById(6);

        $this->assertInstanceOf(EnhancedUser::class, $user);
        $this->assertInstanceOf(Permission::class, $permission);

        $this->assertFalse($user->canById($permission->id));

        self::$enhancedUserMapper->grantPermissionById($user, $permission->id);

        $this->assertTrue($user->canById($permission->id));

        self::$enhancedUserMapper->revokePermissionById($user, $permission->id);

        $this->assertFalse($user->canById($permission->id));
    }

    /**
     * Test revoke permission by name.
     *
     * @return void
     */
    public function testRevokePermissionByName(): void
    {
        $user = self::$enhancedUserMapper->fetchById(7);
        $permission = self::$permissionMapper->fetchById(6);

        $this->assertInstanceOf(EnhancedUser::class, $user);
        $this->assertInstanceOf(Permission::class, $permission);

        $this->assertFalse($user->canByName($permission->name));

        self::$enhancedUserMapper->grantPermissionByName($user, $permission->name);

        $this->assertTrue($user->canByName($permission->name));

        self::$enhancedUserMapper->revokePermissionByName($user, $permission->name);

        $this->assertFalse($user->canByName($permission->name));
    }

    /**
     * Test add role.
     *
     * @return void
     */
    public function testAddRole(): void
    {
        $user = self::$enhancedUserMapper->fetchById(7);
        $role = self::$roleMapper->fetchById(1);

        $this->assertInstanceOf(EnhancedUser::class, $user);
        $this->assertInstanceOf(Role::class, $role);

        $this->assertFalse($user->hasRole($role));

        self::$enhancedUserMapper->addRole($user, $role);

        $this->assertTrue($user->hasRole($role));

        self::$enhancedUserMapper->removeRole($user, $role);

        $this->assertFalse($user->hasRole($role));
    }

    /**
     * Test add role by id.
     *
     * @return void
     */
    public function testAddRoleById(): void
    {
        $user = self::$enhancedUserMapper->fetchById(7);
        $role = self::$roleMapper->fetchById(1);

        $this->assertInstanceOf(EnhancedUser::class, $user);
        $this->assertInstanceOf(Role::class, $role);

        $this->assertFalse($user->hasRoleById($role->id));

        self::$enhancedUserMapper->addRoleById($user, $role->id);

        $this->assertTrue($user->hasRoleById($role->id));

        self::$enhancedUserMapper->removeRoleById($user, $role->id);

        $this->assertFalse($user->hasRoleById($role->id));
    }

    /**
     * Test add role by name.
     *
     * @return void
     */
    public function testAddRoleByName(): void
    {
        $user = self::$enhancedUserMapper->fetchById(7);
        $role = self::$roleMapper->fetchById(1);

        $this->assertInstanceOf(EnhancedUser::class, $user);
        $this->assertInstanceOf(Role::class, $role);

        $this->assertFalse($user->hasRoleByName($role->name));

        self::$enhancedUserMapper->addRoleByName($user, $role->name);

        $this->assertTrue($user->hasRoleByName($role->name));

        self::$enhancedUserMapper->removeRoleByName($user, $role->name);

        $this->assertFalse($user->hasRoleByName($role->name));
    }

    /**
     * Test remove role.
     *
     * @return void
     */
    public function testRemoveRole(): void
    {
        $user = self::$enhancedUserMapper->fetchById(7);
        $role = self::$roleMapper->fetchById(1);

        $this->assertInstanceOf(EnhancedUser::class, $user);
        $this->assertInstanceOf(Role::class, $role);

        $this->assertFalse($user->hasRole($role));

        self::$enhancedUserMapper->addRole($user, $role);

        $this->assertTrue($user->hasRole($role));

        self::$enhancedUserMapper->removeRole($user, $role);

        $this->assertFalse($user->hasRole($role));
    }

    /**
     * Test remove role by id.
     *
     * @return void
     */
    public function testRemoveRoleById(): void
    {
        $user = self::$enhancedUserMapper->fetchById(7);
        $role = self::$roleMapper->fetchById(1);

        $this->assertInstanceOf(EnhancedUser::class, $user);
        $this->assertInstanceOf(Role::class, $role);

        $this->assertFalse($user->hasRoleById($role->id));

        self::$enhancedUserMapper->addRoleById($user, $role->id);

        $this->assertTrue($user->hasRoleById($role->id));

        self::$enhancedUserMapper->removeRoleById($user, $role->id);

        $this->assertFalse($user->hasRoleById($role->id));
    }

    /**
     * Test remove role by name.
     *
     * @return void
     */
    public function testRemoveRoleByName(): void
    {
        $user = self::$enhancedUserMapper->fetchById(7);
        $role = self::$roleMapper->fetchById(1);

        $this->assertInstanceOf(EnhancedUser::class, $user);
        $this->assertInstanceOf(Role::class, $role);

        $this->assertFalse($user->hasRoleByName($role->name));

        self::$enhancedUserMapper->addRoleByName($user, $role->name);

        $this->assertTrue($user->hasRoleByName($role->name));

        self::$enhancedUserMapper->removeRoleByName($user, $role->name);

        $this->assertFalse($user->hasRoleByName($role->name));
    }
}
