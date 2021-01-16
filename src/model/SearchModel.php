<?php

namespace App\model;

use App\exception\CustomException;
use Psr\Container\ContainerInterface;

class SearchModel
{
    /** @var  \Predis\Client $redis */
    private $redis;
    /** @var \PDO $dbConnection */
    private $dbConnection;
    private $severities;
    private $cpes;
    const REDIS_NOT_ACTIVE = -1;
    const NOT_EXIST_ON_REDIS = 0;

    public function __construct(ContainerInterface $container)
    {
        $this->dbConnection = $container->get('db');
        $this->redis = $container->get('redis');

        $this->severities = [
            0 => [
                'severity' => 'UNDEFINED',
                'label' => 'default'
            ],
            1 => [
                'severity' => 'LOW',
                'label' => 'success',
                'rowSeverityClass' => 'success'
            ],
            2 => [
                'severity' => 'MEDIUM',
                'label' => 'info',
                'rowSeverityClass' => 'info'
            ],
            3 => [
                'severity' => 'HIGH',
                'label' => 'warning',
                'rowSeverityClass' => 'warning'
            ],
            4 => [
                'severity' => 'CRITICAL',
                'label' => 'danger',
                'rowSeverityClass' => 'danger'
            ]
        ];
        $this->cpes = [
            'a' => [
                'name' => 'APP',
                'label' => 'info',
                'class' => 'primary'
            ],
            'h' => [
                'name' => 'HW',
                'label' => 'info',
                'class' => 'info'
            ],
            'o' => [
                'name' => 'OS',
                'label' => 'info',
                'class' => 'info'
            ]
        ];
    }

    public function search($param)
    {
        if (strpos($param, 'CVE-') !== false) {

            $redisResult = $this->fetchFromRedis($param);

            if ($redisResult === self::REDIS_NOT_ACTIVE) {
                return $this->searchCve($param);
            } elseif ($redisResult === self::NOT_EXIST_ON_REDIS) {
                $cveResult = $this->searchCve($param);
                $this->redis->set($param, json_encode($cveResult));
                return $cveResult;
            }

            return $redisResult;

        } elseif (strpos($param, ':') !== false) {

            $redisResult = $this->fetchFromRedis($param);

            if ($redisResult === self::REDIS_NOT_ACTIVE) {

                return $this->searchCveConfigurationsWithVersion($param);
            } elseif ($redisResult === self::NOT_EXIST_ON_REDIS) {
                $result = $this->searchCveConfigurationsWithVersion($param);
                $this->redis->set($param, json_encode($result));
                return $result;
            }

            return $redisResult;

        } else {

            $redisResult = $this->fetchFromRedis($param);

            if ($redisResult === self::REDIS_NOT_ACTIVE) {

                $result = $this->searchNpmVulnerabilities($param);
                $result += $this->searchCveConfigurations($param);

                return $result;
            } elseif ($redisResult === self::NOT_EXIST_ON_REDIS) {

                $result = $this->searchNpmVulnerabilities($param);
                $result += $this->searchCveConfigurations($param);

                $this->redis->set($param, json_encode($result));
                return $result;
            }

            return $redisResult;
        }
    }

    public function fetchFromRedis($param)
    {
        if ($this->redis) {
            $result = $this->redis->get($param);

            if ($result) {
                return json_decode($result, true);
            }

            return self::NOT_EXIST_ON_REDIS;
        }

        return self::REDIS_NOT_ACTIVE;
    }

    public function searchCve($cve)
    {
        $duplicateControl = [];

        $sql = "SELECT c.cve,
                       CONCAT(LEFT(c.description, 200), '...') AS description,
                       c.v2Severity,
                       c.v3Severity,
                       cwe.cwe
                FROM cves c
                         INNER JOIN cve_cwes ccwe
                                    ON c.id = ccwe.cve_id
                         INNER JOIN cwes cwe
                                    ON ccwe.cwe_id = cwe.id
                WHERE c.cve = :cve";

        $stm = $this->dbConnection->prepare($sql);
        $stm->bindParam(':cve', $cve, \PDO::PARAM_STR);

        $results = [];

        if (!$stm->execute()) {
            throw CustomException::dbError(503, json_encode($stm->errorInfo()), 'Search could not complete. Please try again!');
        }

        while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {

            if (isset($duplicateControl[$row['cve'] . $row['cwe']])) {
                continue;
            }

            $duplicateControl[$row['cve'] . $row['cwe']] = true;
            $row['severity'] = $row['v3Severity'] == null ? $row['v2Severity'] : $row['v3Severity'];

            if ($row['severity'] == null) {
                $row['severity'] = "<span class='label label-{$this->severities['UNDEFINED']['label']}'>{$this->severities['UNDEFINED']['severity']}</span>";
            } else {
                $tmp = $this->severities[$row['severity']];
                $row['severity'] = "<span class='label label-{$tmp['label']}'>{$tmp['severity']}</span>";
                $row['rowSeverityClass'] = isset($tmp['rowSeverityClass']) ? $tmp['rowSeverityClass'] : null;
            }

            $row['href'] = "/cve/{$row['cve']}";
            $this->unsetCveKeys($row);
            $results[] = $row;
        }

        return $results;
    }

    public function searchCveConfigurationsWithVersion($param)
    {
        $duplicateControl = [];
        $exploded = explode(':', $param);
        $library = "'{$exploded[0]}'";
        $userDefinedVersion = "{$exploded[1]}";

        $sql = "SELECT c.cve,
                       cc.version,
                       CONCAT(LEFT(c.description, 200), '...') AS description,
                       cc.versionStartIncluding,
                       cc.versionEndIncluding,
                       cc.versionStartExcluding,
                       cc.versionEndExcluding,
                       cc.module_name,
                       c.v2Severity,
                       c.v3Severity,
                       cwe.cwe
                FROM cves c
                         INNER JOIN cve_configurations cc
                                    ON c.id = cc.cve_id
                         INNER JOIN cve_cwes ccwe
                                    ON c.id = ccwe.cve_id
                         INNER JOIN cwes cwe
                                    ON ccwe.cwe_id = cwe.id
                WHERE MATCH(cc.product) AGAINST(:libraryName)
                LIMIT 1000";

        $stm = $this->dbConnection->prepare($sql);
        $stm->bindParam(':libraryName', $library, \PDO::PARAM_STR);

        $results = [];

        if (!$stm->execute()) {
            throw CustomException::dbError(503, json_encode($stm->errorInfo()), 'Search could not complete. Please try again!');
        }

        while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {

            $duplicateControlKey = $row['cve'] . '-' . $row['cwe'];

            if (isset($duplicateControl[$duplicateControlKey])) {
                continue;
            }

            $compareResult = $this->compareVersions($userDefinedVersion, $row['versionStartIncluding'], $row['versionEndIncluding'], $row['versionStartExcluding'], $row['versionEndExcluding'], $row['version']);

            if (!$compareResult) {
                continue;
            }

            $duplicateControl[$duplicateControlKey] = true;

            $row['severity'] = $row['v3Severity'] == null ? $row['v2Severity'] : $row['v3Severity'];

            if ($row['severity'] == null) {
                $row['severity'] = "<span class='label label-{$this->severities['UNDEFINED']['label']}'>{$this->severities['UNDEFINED']['severity']}</span>";
            } else {
                $tmp = $this->severities[$row['severity']];
                $row['severity'] = "<span class='label label-{$tmp['label']}'>{$tmp['severity']}</span>";
                $row['rowSeverityClass'] = isset($tmp['rowSeverityClass']) ? $tmp['rowSeverityClass'] : null;
            }

            $row['cveLink'] = "/cve/{$row['cve']}";
            $row['continueToRead'] = "/cve/{$row['cve']}";
            $row['source'] = "<span class='label label-info'>nvd</span>";
            $this->unsetCveKeys($row);
            $results[] = $row;
        }

        return $results;
    }

    public function searchNpmVulnerabilities($param)
    {
        $library = "'$param'";

        $sql = "SELECT npmv.npm_id,
                       cves.cve,
                       npmv.severity,
                       CONCAT(LEFT(npmv.overview, 200), '...') AS description
                FROM npm_vulnerabilities npmv
                         LEFT JOIN cves
                                   ON npmv.cve_id = cves.id
                WHERE MATCH(npmv.product) AGAINST(:libraryName)";

        $stm = $this->dbConnection->prepare($sql);
        $stm->bindParam(':libraryName', $library, \PDO::PARAM_STR);

        $results = [];

        if (!$stm->execute()) {
            throw CustomException::dbError(503, json_encode($stm->errorInfo()), 'Search could not complete. Please try again!');
        }

        while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {

            if ($row['cve'] == null) {
                $row['cve'] = '-';
                $row['cveLink'] = '#';
            } else {
                $row['cveLink'] = "/cve/{$row['cve']}";
            }

            $tmp = $this->severities[$row['severity']];
            $row['severity'] = "<span class='label label-{$tmp['label']}'>{$tmp['severity']}</span>";
            $row['rowSeverityClass'] = isset($tmp['rowSeverityClass']) ? $tmp['rowSeverityClass'] : null;

            $row['source'] = "<span class='label label-primary'>NPM</span>";
            $row['continueToRead'] = "/npm/{$row['npm_id']}";
            $results[] = $row;
        }

        return $results;
    }

    public function searchCveConfigurations($param)
    {
        $duplicateControl = [];
        $library = "'$param'";

        $sql = "SELECT c.cve,
                       cc.version,
                       CONCAT(LEFT(c.description, 200), '...') AS description,
                       cc.versionStartIncluding,
                       cc.versionEndIncluding,
                       cc.versionStartExcluding,
                       cc.versionEndExcluding,
                       cc.module_name,
                       c.v2Severity,
                       c.v3Severity,
                       cwe.cwe
                FROM cves c
                         INNER JOIN cve_configurations cc
                                    ON c.id = cc.cve_id
                         INNER JOIN cve_cwes ccwe
                                    ON c.id = ccwe.cve_id
                         INNER JOIN cwes cwe
                                    ON ccwe.cwe_id = cwe.id
                WHERE MATCH(cc.product) AGAINST(:libraryName)
                LIMIT 1000";

        $stm = $this->dbConnection->prepare($sql);
        $stm->bindParam(':libraryName', $library, \PDO::PARAM_STR);

        $results = [];

        if (!$stm->execute()) {
            throw CustomException::dbError(503, json_encode($stm->errorInfo()), 'Search could not complete. Please try again!');
        }

        while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {

            $duplicateControlKey = $row['cve'] . '-' . $row['cwe'];

            if (isset($duplicateControl[$duplicateControlKey])) {
                continue;
            }

            $duplicateControl[$duplicateControlKey] = true;

            $row['severity'] = $row['v3Severity'] == null ? $row['v2Severity'] : $row['v3Severity'];

            if ($row['severity'] == null) {
                $row['severity'] = "<span class='label label-{$this->severities['UNDEFINED']['label']}'>{$this->severities['UNDEFINED']['severity']}</span>";
            } else {
                $tmp = $this->severities[$row['severity']];
                $row['severity'] = "<span class='label label-{$tmp['label']}'>{$tmp['severity']}</span>";
                $row['rowSeverityClass'] = isset($tmp['rowSeverityClass']) ? $tmp['rowSeverityClass'] : null;
            }

            $row['cveLink'] = "/cve/{$row['cve']}";
            $row['continueToRead'] = "/cve/{$row['cve']}";
            $row['source'] = "<span class='label label-info'>NVD</span>";
            $this->unsetCveKeys($row);
            $results[] = $row;
        }

        return $results;
    }

    public function getReferencesByNpm($npmId)
    {
        $duplicateControl = [];

        $sql = "SELECT link,name,tag  
                FROM npm_references
                WHERE npm_id = :npm_id";

        $stm = $this->dbConnection->prepare($sql);
        $stm->bindParam(':npm_id', $npmId, \PDO::PARAM_INT);

        $references = [];

        if (!$stm->execute()) {
            throw CustomException::dbError(503, json_encode($stm->errorInfo()), 'NPM References could not fetch. Please try again!');
        }

        while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {

            if (isset($duplicateControl[$row['link']])) {
                continue;
            }

            if (substr($row['name'], 0, 1) === "-") {
                $row['name'] = substr($row['name'], 1);
            }

            if ($row['name'] === 'N/A') {
                $row['name'] = $row['link'];
            }

            $references[] = $row;
            $duplicateControl[$row['link']] = true;
        }

        return $references;
    }

    public function getReferencesByCVE($cveId)
    {
        $duplicateControl = [];

        $sql = "SELECT cve, url, `name`, refsource, tags  
                FROM cve_references
                WHERE cve = :cve_id";

        $stm = $this->dbConnection->prepare($sql);
        $stm->bindParam(':cve_id', $cveId, \PDO::PARAM_INT);

        $references = [];

        if (!$stm->execute()) {
            throw CustomException::dbError(503, json_encode($stm->errorInfo()), 'References could not fetch. Please try again!');
        }

        while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {

            if (isset($duplicateControl[$row['url']])) {
                continue;
            }

            if ($row['name'] === 'N/A') {
                $row['name'] = $row['url'];
            }

            $tags = explode(', ', $row['tags']);
            $tagStr = '';

            foreach ($tags as $tag) {
                $tagStr .= "<span class='label label-info'>$tag</span> ";
            }

            $row['tagStr'] = $tagStr;
            $references[] = $row;
            $duplicateControl[$row['url']] = true;
        }

        return $references;
    }

    public function unsetCveKeys(&$row)
    {
        unset($row['cwe']);
        unset($row['module_name']);
        unset($row['v2Severity']);
        unset($row['v3Severity']);
        unset($row['version']);
        unset($row['versionEndExcluding']);
        unset($row['versionEndIncluding']);
        unset($row['versionStartExcluding']);
        unset($row['versionStartIncluding']);
    }

    public function getCwesByCve($cveId)
    {
        $sql = "SELECT *
                FROM cve_cwes cc
                INNER JOIN cwes cwe
                ON cc.cwe_id = cwe.id
                WHERE cc.cve_id = :cve_id";

        $stm = $this->dbConnection->prepare($sql);
        $stm->bindParam(':cve_id', $cveId, \PDO::PARAM_INT);

        $results = [];

        if (!$stm->execute()) {
            throw CustomException::dbError(503, json_encode($stm->errorInfo()), 'Could not fetch CWEs. Please try again!');
        }

        while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {
            $results[] = $row;
        }

        return $results;
    }

    public function compareAttributes($userDefinedVersion, $componentVersion)
    {
        if ($userDefinedVersion === $componentVersion) {
            return true;
        } elseif ($componentVersion === '*') {
            return true;
        }

        return false;
    }

    function parseCPE($cpe)
    {
        return explode(':', $cpe);
    }

    public function compareVersions($userVersion, $versionStartIncluding, $versionEndIncluding, $versionStartExcluding, $versionEndExcluding, $cpeVersion)
    {
        $compareResult = false;

        if ($cpeVersion === '-') {
            return false;
        }

        $control = $versionStartExcluding != null || $versionEndExcluding != null || $versionStartIncluding != null || $versionEndIncluding != null;

        if (!$control) {
            $compareAttributes = $this->compareAttributes($userVersion, $cpeVersion);
            if ($compareAttributes) {
                return true;
            }
        }

        if ($control && $versionEndExcluding != null) {
            if (version_compare($versionEndExcluding, $userVersion, '>')) {
                $compareResult = true;
            } else {
                $compareResult = false;
            }
        }

        if ($control && $versionStartExcluding != null) {
            if (version_compare($versionStartExcluding, $userVersion, '<')) {
                $compareResult = true;
            } else {
                $compareResult = false;
            }
        }

        if ($control && $versionEndIncluding != null) {
            if (version_compare($versionEndIncluding, $userVersion, '>=')) {
                $compareResult = true;
            } else {
                $compareResult = false;
            }
        }

        if ($control && $versionStartIncluding != null) {
            if (version_compare($versionStartIncluding, $userVersion, '<=')) {
                $compareResult = true;
            } else {
                $compareResult = false;
            }
        }

        return $compareResult;
    }

    // TODO deprecated
    public function compareVersionsOld($userVersion, $versionStartIncluding, $versionEndIncluding)
    {
        if ($versionStartIncluding != null && $versionEndIncluding != null) {

            if (version_compare($versionEndIncluding, $userVersion, '>=') && version_compare($versionStartIncluding, $userVersion, '<=')) {
                return true;
            }

        } elseif ($versionStartIncluding == null && $versionEndIncluding != null) {

            if (version_compare($versionEndIncluding, $userVersion, '>=')) {
                return true;
            }

        } elseif ($versionStartIncluding != null && $versionEndIncluding == null) {

            if (version_compare($versionStartIncluding, $userVersion, '<=')) {
                return true;
            }

        } elseif ($versionStartIncluding == null && $versionEndIncluding == null) {
            return true;
        }

        return false;
    }

    public function insertSearchQuery($query)
    {
        $created = time();

        $sql = 'INSERT INTO search_params (query, created) 
                VALUES (:query, :created)';

        $stm = $this->dbConnection->prepare($sql);
        $stm->bindParam(':query', $query, \PDO::PARAM_STR);
        $stm->bindParam(':created', $created, \PDO::PARAM_INT);

        if ($stm->execute()) {
            return true;
        }

        return false;
    }
}