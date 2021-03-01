<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit1310000c21164033f56e5c4a2b6ae71d
{
    public static $files = array (
        'decc78cc4436b1292c6c0d151b19445c' => __DIR__ . '/..' . '/phpseclib/phpseclib/phpseclib/bootstrap.php',
    );

    public static $prefixLengthsPsr4 = array (
        'p' => 
        array (
            'phpseclib\\' => 10,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'phpseclib\\' => 
        array (
            0 => __DIR__ . '/..' . '/phpseclib/phpseclib/phpseclib',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit1310000c21164033f56e5c4a2b6ae71d::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit1310000c21164033f56e5c4a2b6ae71d::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInit1310000c21164033f56e5c4a2b6ae71d::$classMap;

        }, null, ClassLoader::class);
    }
}