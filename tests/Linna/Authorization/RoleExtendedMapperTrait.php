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

use Linna\Storage\ExtendedPDO;

/**
 * Role Extended Mapper Trait.
 */
trait RoleExtendedMapperTrait
{
    /** @var ExtendedPDO Database connection. */
    protected static ExtendedPDO $pdo;

    /** @var PermissionMapper The permission mapper class. */
    protected static PermissionMapper $permissionMapper;

    /** @var UserMapper The user mapper class. */
    protected static UserMapper $userMapper;

    /** @var RoleExtendedMapper The role mapper class. */
    protected static RoleExtendedMapper $roleExtendedMapper;

    /**
     * Test new instance.
     */
    public function testNewInstance()
    {
        $this->assertInstanceOf(RoleExtendedMapper::class, self::$roleExtendedMapper);
    }


    /**
     * Role Permission provider.
     *
     * @return array
     */
    public static function rolePermissionProvider(): array
    {
        $role = new RoleExtended(id: 2, name: 'Power Users');
        $permission = new Permission(id: 3, name: 'delete user');

        return [
            [$role, $permission]
        ];
    }

    /**
     * Test grant permission.
     *
     * @dataProvider rolePermissionProvider
     *
     * @return void
     */
    public function testGrantPermission(RoleExtended $role, Permission $permission): void
    {
        self::$roleExtendedMapper->grantPermission($role, $permission);

        $this->assertTrue($role->can($permission));
    }

    /**
     * Test grant permission by id.
     *
     * @dataProvider rolePermissionProvider
     *
     * @return void
     */
    public function testGrantPermissionById(RoleExtended $role, Permission $permission): void
    {
        self::$roleExtendedMapper->grantPermissionById($role, $permission->id);

        $this->assertTrue($role->canById($permission->id));
    }

    /**
     * Test grant permission by name.
     *
     * @dataProvider rolePermissionProvider
     *
     * @return void
     */
    public function testGrantPermissionByName(RoleExtended $role, Permission $permission): void
    {
        self::$roleExtendedMapper->grantPermissionByName($role, $permission->name);

        $this->assertTrue($role->canByName($permission->name));
    }

    /**
     * Test revoke permission.
     *
     * @dataProvider rolePermissionProvider
     *
     * @return void
     */
    public function testRevokePermission(RoleExtended $role, Permission $permission): void
    {
        self::$roleExtendedMapper->grantPermission($role, $permission);

        $this->assertTrue($role->can($permission));

        self::$roleExtendedMapper->revokePermission($role, $permission);

        $this->assertFalse($role->can($permission));
    }

    /**
     * Test revoke permission by id.
     *
     * @dataProvider rolePermissionProvider
     *
     * @return void
     */
    public function testRevokePermissionById(RoleExtended $role, Permission $permission): void
    {
        self::$roleExtendedMapper->grantPermissionById($role, $permission->id);

        $this->assertTrue($role->canById($permission->id));

        self::$roleExtendedMapper->revokePermissionById($role, $permission->id);

        $this->assertFalse($role->canById($permission->id));
    }

    /**
     * Test revoke permission by name.
     *
     * @dataProvider rolePermissionProvider
     *
     * @return void
     */
    public function testRevokePermissionByName(RoleExtended $role, Permission $permission): void
    {
        self::$roleExtendedMapper->grantPermissionByName($role, $permission->name);

        $this->assertTrue($role->canByName($permission->name));

        self::$roleExtendedMapper->revokePermissionByName($role, $permission->name);

        $this->assertFalse($role->canByName($permission->name));
    }

    /**
     * Role User provider.
     *
     * @return array
     */
    public static function roleUserProvider(): array
    {
        $role = new RoleExtended(id: 2, name: 'Power Users');
        $user = new UserExtended(id: 7, name: 'User_5');

        return [
            [$role, $user]
        ];
    }

    /**
     * Test add user.
     *
     * @dataProvider roleUserProvider
     *
     * @return void
     */
    public function testAddUser(RoleExtended $role, User $user): void
    {
        self::$roleExtendedMapper->addUser($role, $user);

        $this->assertTrue($role->hasUser($user));
    }

    /**
     * Test add user by id.
     *
     * @dataProvider roleUserProvider
     *
     * @return void
     */
    public function testAddUserById(RoleExtended $role, User $user): void
    {
        self::$roleExtendedMapper->addUserById($role, $user->id);

        $this->assertTrue($role->hasUserById($user->id));
    }

    /**
     * Test add user by name.
     *
     * @dataProvider roleUserProvider
     *
     * @return void
     */
    public function testAddUserByName(RoleExtended $role, User $user): void
    {
        self::$roleExtendedMapper->addUserByName($role, $user->name);

        $this->assertTrue($role->hasUserByName($user->name));
    }



    /**
     * Test remove user.
     *
     * @dataProvider roleUserProvider
     *
     * @return void
     */
    public function testRemoveUser(RoleExtended $role, User $user): void
    {
        self::$roleExtendedMapper->addUser($role, $user);

        $this->assertTrue($role->hasUser($user));

        self::$roleExtendedMapper->removeUser($role, $user);

        $this->assertFalse($role->hasUser($user));
    }

    /**
     * Test remove user by id.
     *
     * @dataProvider roleUserProvider
     *
     * @return void
     */
    public function testRemoveUserById(RoleExtended $role, User $user): void
    {
        self::$roleExtendedMapper->addUserById($role, $user->id);

        $this->assertTrue($role->hasUserById($user->id));

        self::$roleExtendedMapper->removeUserById($role, $user->id);

        $this->assertFalse($role->hasUserById($user->id));
    }

    /**
     * Test remove user by name.
     *
     * @dataProvider roleUserProvider
     *
     * @return void
     */
    public function testRemoveUserByName(RoleExtended $role, User $user): void
    {
        self::$roleExtendedMapper->addUserByName($role, $user->name);

        $this->assertTrue($role->hasUserByName($user->name));

        self::$roleExtendedMapper->removeUserByName($role, $user->name);

        $this->assertFalse($role->hasUserByName($user->name));
    }
}
