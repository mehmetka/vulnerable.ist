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

    public function cveDetail(ServerRequestInterface $request, ResponseInterface $response, $args)
    {
        $cve = str_replace('cve-', 'CVE-', $args['cve']);

        $details = $this->searchModel->cveDetails($cve);
        $this->data['title'] = $details['cve'];
        $this->data['data'] = $details;

        return $this->view->render($response, 'cve-details.mustache', $this->data);
    }

    public function npmDetail(ServerRequestInterface $request, ResponseInterface $response, $args)
    {
        $npmId = $args['npm'];
        $details = $this->searchModel->npmDetails($npmId);

        $this->data['title'] = 'Npm Detail';
        $this->data['data'] = $details;

        return $this->view->render($response, 'npm-details.mustache', $this->data);
    }

}