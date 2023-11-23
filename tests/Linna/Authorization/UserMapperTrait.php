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
use Linna\DataMapper\Uuid4;
use Linna\DataMapper\Exception\NullDomainObjectException;
use Linna\Storage\ExtendedPDO;

/**
 * User Mapper trait.
 */
trait UserMapperTrait
{
    /** @var ExtendedPDO Database connection. */
    protected static ExtendedPDO $pdo;

    /** @var UserMapper The enhanced authentication mapper class. */
    protected static UserMapper $userMapper;

    /**
     * Test new instance.
     *
     * @return void
     */
    public function testNewInstance(): void
    {
        $this->assertInstanceOf(UserMapper::class, self::$userMapper);
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
            [2, 2],
            [3, 3],
            [4, 4],
            [5, 5],
            [6, 6],
            [7, 7],
            [8, 0],
            [9, 0]
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
        $user = self::$userMapper->fetchById($userId);

        if ($expectedId === 0) {
            $this->assertInstanceOf(NullDomainObject::class, $user);
            $this->expectException(NullDomainObjectException::class);
        }

        $this->assertEquals($user->getId(), $expectedId);
    }

    /**
     * User name provider
     *
     * @return array
     */
    public static function userNameProvider(): array
    {
        return [
            ['root', 'root'],
            ['User_0', 'User_0'],
            ['User_1', 'User_1'],
            ['User_2', 'User_2'],
            ['User_3', 'User_3'],
            ['User_4', 'User_4'],
            ['User_5', 'User_5'],
            ['bad_name_1', ''],
            ['bad_name_2', '']
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
        $user = self::$userMapper->fetchByName($userName);

        if ($expectedName === '') {
            $this->assertInstanceOf(NullDomainObject::class, $user);
        }

        $this->assertEquals($user->name, $expectedName);
    }

    /**
     * Test fetch all.
     *
     * @return void
     */
    public function testFetchAll(): void
    {
        $this->assertCount(7, self::$userMapper->fetchAll());
    }

    /**
     * User fetch limit provider.
     *
     * @return array
     */
    public static function userFetchLimitProvider(): array
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
        $users = self::$userMapper->fetchLimit($offset, $rowCount);

        $key = \array_keys($users)[0];

        $this->assertCount(1, $users);
        $this->assertEquals($users[$key]->name, $userName);
    }

    /**
     * Test concrete create.
     *
     * @return void
     */
    public function testConcreteCreate(): void
    {
        $this->assertInstanceOf(User::class, self::$userMapper->create());
    }

    /**
     * Test concrete insert.
     *
     * @return void
     */
    public function testConcreteInsert(): void
    {
        //create user
        $user = self::$userMapper->create();
        $user->uuid = (new UUID4())->getHex();
        $user->name = 'test_user';
        $user->description = 'test_user description';
        $user->email = 'test_user@email.com';
        $user->active = 1;
        $user->setPassword('test_password');

        //check for clean user
        $this->assertSame(null, $user->getId());

        self::$userMapper->save($user);

        //check if saved
        $this->assertGreaterThan(0, $user->getId());

        //get one more time the user
        $userStored = self::$userMapper->fetchByName('test_user');

        //check
        $this->assertInstanceOf(User::class, $userStored);
        $this->assertSame($user->id, $userStored->id);
        $this->assertSame($user->uuid, $userStored->uuid);
        $this->assertSame($user->name, $user->name);
        $this->assertSame($user->description, $user->description);
        $this->assertSame($user->email, $user->email);
        $this->assertSame($user->password, $user->password);
        $this->assertSame($user->active, $user->active);

        //clean
        self::$userMapper->delete($userStored);
    }

    /**
     * Test concrete update.
     *
     * @return void
     */
    public function testConcreteUpdate(): void
    {
        $user = self::$userMapper->create();
        $user->uuid = (new UUID4())->getHex();
        $user->name = 'test_user';
        $user->description = 'test_user description';
        $user->email = 'test_user@email.com';
        $user->active = 1;
        $user->setPassword('test_password');

        self::$userMapper->save($user);

        $userStored = self::$userMapper->fetchByName('test_user');

        $this->assertInstanceOf(User::class, $userStored);

        $userStored->name = 'test_user_update';
        $userStored->description = 'test_user_update description';
        $userStored->email = 'test_user_update@email.com';
        $userStored->active = 0;
        $userStored->setPassword('test_password_update');

        self::$userMapper->save($userStored);

        $userStoredUpdated = self::$userMapper->fetchByName('test_user_update');

        $this->assertInstanceOf(User::class, $userStoredUpdated);
        $this->assertSame($userStoredUpdated->id, $userStored->id);
        $this->assertSame($userStoredUpdated->uuid, $userStored->uuid);
        $this->assertSame($userStoredUpdated->name, $userStored->name);
        $this->assertSame($userStoredUpdated->description, $userStored->description);
        $this->assertSame($userStoredUpdated->email, $userStored->email);
        $this->assertSame($userStoredUpdated->password, $userStored->password);
        $this->assertSame($userStoredUpdated->active, $userStored->active);

        //clean
        self::$userMapper->delete($userStored);
    }
}
