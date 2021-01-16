<?php

namespace App\controller;

use App\model\SearchModel;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class SearchController extends Controller
{
    public $searchModel;

    public function __construct(ContainerInterface $container)
    {
        parent::__construct($container);
        $this->searchModel = new SearchModel($container);
    }

    public function index(ServerRequestInterface $request, ResponseInterface $response)
    {
        $this->data['title'] = 'Search Vulnerable Libraries';

        return $this->view->render($response, 'search.mustache', $this->data);
    }

    public function search(ServerRequestInterface $request, ResponseInterface $response)
    {
        $params = $request->getParsedBody();
        $this->searchModel->insertSearchQuery($params['param']);
        $list = $this->searchModel->search($params['param']);
        $count = count($list);

        if ($count == 0) {
            $resultCount = 'No Result';
        } elseif (count($list) == 1) {
            $resultCount = '1 Result';
        } else {
            $resultCount = $count . ' Results';
        }

        $resource = [
            "count" => $resultCount,
            "data" => $list,
        ];

        return $this->response(200, $resource);
    }

}