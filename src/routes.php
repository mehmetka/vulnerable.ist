<?php

use App\controller;

$app->group('', function () {

    $this->get('/', controller\SearchController::class . ':index')->setName('home');
    $this->post('/search', controller\SearchController::class . ':search');

    $this->get('/cve/{cve}', controller\SearchController::class . ':cveDetail');
    $this->get('/npm/{npm:[0-9]+}', controller\SearchController::class . ':npmDetail');

});