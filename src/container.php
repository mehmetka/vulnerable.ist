<?php

use App\exception\CustomException;

$container['db'] = function ($container) {

    $settings = $container->get('settings')['db'];

    $dsn = $settings['driver'] . ":host=" . $settings['host'] . ";dbname=" . $settings['database'] . ";charset=" . $settings['charset'];
    try {
        $db = new \PDO($dsn, $settings['user'], $settings['password']);
    } catch (\Exception $e) {
        throw new Exception("Database access problem : " . $e->getMessage(), 500);
    }
    return $db;
};

$container['logger'] = function ($container) {
    $logger = new Monolog\Logger('vulnerable.ist');
    $logger->pushProcessor(new Monolog\Processor\UidProcessor());
    $logger->pushHandler(new Monolog\Handler\StreamHandler(__DIR__ . '/../logs/web.log', \Monolog\Logger::DEBUG));
    return $logger;
};

$container['view'] = function ($container) {

    return $view = new \Slim\Views\Mustache([
        'template' => [
            'paths' => [
                realpath(__DIR__ . '/../views/includes'),
                realpath(__DIR__ . '/../views/modals'),
                realpath(__DIR__ . '/../views')
            ],
            'extension' => 'mustache',
            'charset' => 'utf-8'
        ]
    ]);

};

$container['errorHandler'] = function ($container) {

    return function ($request, $response, $exception) use ($container) {

        /** @var Monolog\Logger $logger */
        $logger = $container->get('logger');

        /** @var Exception $exception */
        if ($exception instanceof CustomException) {

            $withStatus = $exception->getHttpStatusCode();

            if ($exception->getErrorType() == 'client_error') {
                $data['status'] = 400;
                $logger->warning($exception->getMessage() . " detail:" . $exception->getErrorDetail() . ' trace:' . $exception->getBackTrace());
            }

            if ($exception->getErrorType() == 'server_error') {
                $data['status'] = 500;
                $logger->error($exception->getMessage() . " detail:" . $exception->getErrorDetail() . ' trace:' . $exception->getBackTrace());
            }

            if ($exception->getErrorType() == 'db_error') {
                $data['status'] = 503;
                $logger->critical($exception->getMessage() . " detail:" . $exception->getErrorDetail() . ' trace:' . $exception->getBackTrace());
            }

            $data = [
                'status' => $withStatus,
                'message' => $exception->getMessage()
            ];

        } else {

            $logger->critical($exception->getMessage());
            $withStatus = 500;

            $data = [
                'status' => $withStatus,
                'message' => $exception->getMessage()
            ];
        }

        return $container->get('response')->withStatus($data['status'])->withHeader('Content-Type', 'application/json')->write(json_encode($data));
    };
};

$container['notFoundHandler'] = function ($container) {
    throw CustomException::notFound(404, "Not Found!");
};

$container['redis'] = function ($c) {
    $settings = $c->get('settings')['redis'];
    $redis = null;

    if ($settings['active']) {
        try {
            $redis = new \Predis\Client($settings);
        } catch (\Exception $e) {
            throw new Exception("Could not connect to Redis - " . $e->getMessage(), 5000);
        }
    }

    return $redis;
};