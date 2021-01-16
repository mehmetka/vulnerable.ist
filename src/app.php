<?php

date_default_timezone_set('Europe/Istanbul');

require __DIR__ . '/../vendor/autoload.php';

$settings = [];
$settings = parse_ini_file(__DIR__ . '/../conf/conf.ini', true);

$settings = [
    'settings' => $settings
];

$app = new Slim\App($settings);

$container = $app->getContainer();

require __DIR__ . '/container.php';
require __DIR__ . '/routes.php';
