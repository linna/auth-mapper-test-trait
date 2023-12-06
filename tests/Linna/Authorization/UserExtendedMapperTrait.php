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
use Linna\Storage\ExtendedPDO;

/**
 * User Extended Mapper Trait.
 */
trait UserExtendedMapperTrait
{
    /** @var ExtendedPDO Database connection. */
    protected static ExtendedPDO $pdo;

    /** @var PermissionMapper The permission mapper class. */
    protected static PermissionMapper $permissionMapper;

    /** @var RoleMapper The role mapper class. */
    protected static RoleMapper $roleMapper;

    /** @var UserExtendedMapper The user extended mapper class. */
    protected static UserExtendedMapper $userExtendedMapper;

    /**
     * Test new instance.
     */
    public function testNewInstance()
    {
        $this->assertInstanceOf(UserExtendedMapper::class, self::$userExtendedMapper);
    }

    /**
     * User Permission provider.
     *
     * @return array
     */
    public static function userPermissionProvider(): array
    {
        $user = new UserExtended(id:7, name: 'User_5');
        $permission = new Permission(id: 6, name: 'disable user');

        return [
            [$user, $permission]
        ];
    }

    /**
     * Test grant permission.
     *
     * @dataProvider userPermissionProvider
     *
     * @return void
     */
    public function testGrantPermission(UserExtended $user, Permission $permission): void
    {
        self::$userExtendedMapper->grantPermission($user, $permission);

        $this->assertTrue($user->can($permission));
    }

    /**
     * Test grant permission by id.
     *
     * @dataProvider userPermissionProvider
     *
     * @return void
     */
    public function testGrantPermissionById(UserExtended $user, Permission $permission): void
    {
        self::$userExtendedMapper->grantPermissionById($user, $permission->id);

        $this->assertTrue($user->canById($permission->id));
    }

    /**
     * Test grant permission by name.
     *
     * @dataProvider userPermissionProvider
     *
     * @return void
     */
    public function testGrantPermissionByName(UserExtended $user, Permission $permission): void
    {
        self::$userExtendedMapper->grantPermissionByName($user, $permission->name);

        $this->assertTrue($user->canByName($permission->name));
    }

    /**
     * Test revoke permission.
     *
     * @dataProvider userPermissionProvider
     *
     * @return void
     */
    public function testRevokePermission(UserExtended $user, Permission $permission): void
    {
        //$this->assertFalse($user->can($permission));

        self::$userExtendedMapper->grantPermission($user, $permission);

        $this->assertTrue($user->can($permission));

        self::$userExtendedMapper->revokePermission($user, $permission);

        $this->assertFalse($user->can($permission));
    }

    /**
     * Test revoke permission by id.
     *
     * @dataProvider userPermissionProvider
     *
     * @return void
     */
    public function testRevokePermissionById(UserExtended $user, Permission $permission): void
    {
        //$this->assertFalse($user->canById($permission->id));

        self::$userExtendedMapper->grantPermissionById($user, $permission->id);

        $this->assertTrue($user->canById($permission->id));

        self::$userExtendedMapper->revokePermissionById($user, $permission->id);

        $this->assertFalse($user->canById($permission->id));
    }

    /**
     * Test revoke permission by name.
     *
     * @dataProvider userPermissionProvider
     *
     * @return void
     */
    public function testRevokePermissionByName(UserExtended $user, Permission $permission): void
    {
        //$this->assertFalse($user->canByName($permission->name));

        self::$userExtendedMapper->grantPermissionByName($user, $permission->name);

        $this->assertTrue($user->canByName($permission->name));

        self::$userExtendedMapper->revokePermissionByName($user, $permission->name);

        $this->assertFalse($user->canByName($permission->name));
    }

    /**
     * User Role provider.
     *
     * @return array
     */
    public static function userRoleProvider(): array
    {
        $user = new UserExtended(id:7, name: 'User_5');
        $role = new Role(id: 1, name: 'Administrator');

        return [
            [$user, $role]
        ];
    }

    /**
     * Test add role.
     *
     * @dataProvider userRoleProvider
     *
     * @return void
     */
    public function testAddRole(UserExtended $user, Role $role): void
    {
        self::$userExtendedMapper->addRole($user, $role);

        $this->assertTrue($user->hasRole($role));
    }

    /**
     * Test add role by id.
     *
     * @dataProvider userRoleProvider
     *
     * @return void
     */
    public function testAddRoleById(UserExtended $user, Role $role): void
    {
        self::$userExtendedMapper->addRoleById($user, $role->id);

        $this->assertTrue($user->hasRoleById($role->id));
    }

    /**
     * Test add role by name.
     *
     * @dataProvider userRoleProvider
     *
     * @return void
     */
    public function testAddRoleByName(UserExtended $user, Role $role): void
    {
        $this->assertFalse($user->hasRoleByName($role->name));

        self::$userExtendedMapper->addRoleByName($user, $role->name);
    }

    /**
     * Test remove role.
     *
     * @dataProvider userRoleProvider
     *
     * @return void
     */
    public function testRemoveRole(UserExtended $user, Role $role): void
    {
        self::$userExtendedMapper->addRole($user, $role);

        $this->assertTrue($user->hasRole($role));

        self::$userExtendedMapper->removeRole($user, $role);

        $this->assertFalse($user->hasRole($role));
    }

    /**
     * Test remove role by id.
     *
     * @dataProvider userRoleProvider
     *
     * @return void
     */
    public function testRemoveRoleById(UserExtended $user, Role $role): void
    {
        self::$userExtendedMapper->addRoleById($user, $role->id);

        $this->assertTrue($user->hasRoleById($role->id));

        self::$userExtendedMapper->removeRoleById($user, $role->id);

        $this->assertFalse($user->hasRoleById($role->id));
    }

    /**
     * Test remove role by name.
     *
     * @dataProvider userRoleProvider
     *
     * @return void
     */
    public function testRemoveRoleByName(UserExtended $user, Role $role): void
    {
        self::$userExtendedMapper->addRoleByName($user, $role->name);

        $this->assertTrue($user->hasRoleByName($role->name));

        self::$userExtendedMapper->removeRoleByName($user, $role->name);

        $this->assertFalse($user->hasRoleByName($role->name));
    }
}
