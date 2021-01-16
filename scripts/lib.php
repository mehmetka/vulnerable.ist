<?php

define('ERROR_OCCURED', -1);
define('NPM', 0);
define('NVD', 1);

define('PKG_NPM', 0);
define('PKG_MAVEN', 1);

define('VULNERABLE_NO', 0);
define('VULNERABLE', 1);
define('VULNERABLE_UNDEFINED', 2);
/*
    APPLICATION("a"),
    OPERATING_SYSTEM("o"),
    HARDWARE_DEVICE("h"),
    ANY("*"),
    NA("-");
 */

$severities = [
    'CRITICAL' => 4,
    'HIGH' => 3,
    'MEDIUM' => 2,
    'LOW' => 1
];

$types = [
    'a' => 0,
    'o' => 1,
    'h' => 2,
    'unrecognized' => 3
];

$operators = [
    'AND' => 0,
    'OR' => 1
];

function downloadFile($link, $filePath, $auth = null)
{
    $guzzle = $GLOBALS['guzzle'];
    $settings = $GLOBALS['settings'];
    $logger = $GLOBALS['logger'];

    $filePath = fopen($filePath, 'w');

    $requestBody['save_to'] = $filePath;

    if ($auth) {
        $requestBody['auth'][] = $auth['username'];
        $requestBody['auth'][] = $auth['password'];
    }

    if (isset($settings['guzzle']) && !$settings['guzzle']['proxy']) {
        $logger->info('[FileDownload] No proxy');
        $requestBody['proxy'] = '';
    }

    $logger->info("[FileDownload] Downloading [$link] file and saving to => $filePath");

    try {

        $response = $guzzle->request('GET', $link, $requestBody);
        $body = $response->getBody();

        $statusCode = $response->getStatusCode();

        $response = json_decode($body, true);
        $response['code'] = $statusCode;

    } catch (Exception\ClientException $exception) {
        $logger->error('[Client] Request: ' . Psr7\str($exception->getRequest()));
        $logger->error('[Client] Response: ' . Psr7\str($exception->getResponse()));
        return -1;
    } catch (Exception\ServerException $exception) {
        $logger->error('[Server] Request: ' . Psr7\str($exception->getRequest()));
        $logger->error('[Server] Response: ' . Psr7\str($exception->getResponse()));
        return -1;
    } catch (Exception\RequestException $exception) {
        $logger->error('[Request] Request: ' . Psr7\str($exception->getRequest()));
        $logger->error('[Request] Response: ' . Psr7\str($exception->getResponse()));
        return -1;
    }

    return $response;
}

function saveNpmVulnerability($npm)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $sql = 'INSERT INTO npm_vulnerabilities (uid, npm_id, title_id, vendor, product, module_name, library_id, cve_id, cwe_id, found_by_id, reported_by_id, severity, vulnerable_versions, patched_versions, exploitability, overview, recommendation, created, updated, deleted)
            VALUES (UUID(), :npm_id, :title_id, :vendor, :product, :module_name, :library_id, :cve_id, :cwe_id, :found_by_id, :reported_by_id, :severity, :vulnerable_versions, :patched_versions, :exploitability, :overview, :recommendation, :created, :updated, :deleted)';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(":npm_id", $npm['npm_id'], \PDO::PARAM_INT);
    $stm->bindParam(":title_id", $npm['title_id'], \PDO::PARAM_INT);
    $stm->bindParam(":vendor", $npm['vendor'], \PDO::PARAM_STR);
    $stm->bindParam(":product", $npm['product'], \PDO::PARAM_STR);
    $stm->bindParam(":module_name", $npm['module_name'], \PDO::PARAM_STR);
    $stm->bindParam(":library_id", $npm['libraryId'], \PDO::PARAM_INT);
    $stm->bindParam(":cve_id", $npm['cve_id'], \PDO::PARAM_INT);
    $stm->bindParam(":cwe_id", $npm['cwe_id'], \PDO::PARAM_INT);
    $stm->bindParam(":found_by_id", $npm['found_by_id'], \PDO::PARAM_INT);
    $stm->bindParam(":reported_by_id", $npm['reported_by_id'], \PDO::PARAM_INT);
    $stm->bindParam(":severity", $npm['severity'], \PDO::PARAM_INT);
    $stm->bindParam(":vulnerable_versions", $npm['vulnerable_versions'], \PDO::PARAM_STR);
    $stm->bindParam(":patched_versions", $npm['patched_versions'], \PDO::PARAM_STR);
    $stm->bindParam(":exploitability", $npm['exploitability'], \PDO::PARAM_INT);
    $stm->bindParam(":overview", $npm['overview'], \PDO::PARAM_STR);
    $stm->bindParam(":recommendation", $npm['recommendation'], \PDO::PARAM_STR);
    $stm->bindParam(":created", $npm['created'], \PDO::PARAM_STR);
    $stm->bindParam(":updated", $npm['updated'], \PDO::PARAM_STR);
    $stm->bindParam(":deleted", $npm['deleted'], \PDO::PARAM_STR);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not save Npm Vulnerability. Details: ' . json_encode($stm->errorInfo()));
        return false;
    }

    return true;
}

function saveCve($cve)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $sql = 'INSERT INTO cves (uid, cve, v3Severity, v2Severity, v3VectorString, v2VectorString, v3BaseScore, v2BaseScore, v3ExploitabilityScore, v2ExploitabilityScore, v3ImpactScore, v2ImpactScore, description, created, updated)
            VALUES (UUID(), :cve, :v3Severity, :v2Severity, :v3VectorString, :v2VectorString, :v3BaseScore, :v2BaseScore, :v3ExploitabilityScore, :v2ExploitabilityScore, :v3ImpactScore, :v2ImpactScore, :description, :created, :updated)';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(":cve", $cve['cve'], \PDO::PARAM_STR);
    $stm->bindParam(":v3Severity", $cve['v3Severity'], \PDO::PARAM_INT);
    $stm->bindParam(":v2Severity", $cve['v2Severity'], \PDO::PARAM_INT);
    $stm->bindParam(":v3VectorString", $cve['v3VectorString'], \PDO::PARAM_STR);
    $stm->bindParam(":v2VectorString", $cve['v2VectorString'], \PDO::PARAM_STR);
    $stm->bindParam(":v3BaseScore", $cve['v3BaseScore'], \PDO::PARAM_STR);
    $stm->bindParam(":v2BaseScore", $cve['v2BaseScore'], \PDO::PARAM_STR);
    $stm->bindParam(":v3ExploitabilityScore", $cve['v3ExploitabilityScore'], \PDO::PARAM_STR);
    $stm->bindParam(":v2ExploitabilityScore", $cve['v2ExploitabilityScore'], \PDO::PARAM_STR);
    $stm->bindParam(":v3ImpactScore", $cve['v3ImpactScore'], \PDO::PARAM_STR);
    $stm->bindParam(":v2ImpactScore", $cve['v2ImpactScore'], \PDO::PARAM_STR);
    $stm->bindParam(":description", $cve['description'], \PDO::PARAM_STR);
    $stm->bindParam(":created", $cve['created'], \PDO::PARAM_STR);
    $stm->bindParam(":updated", $cve['updated'], \PDO::PARAM_STR);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not save CVE. Details: ' . json_encode($stm->errorInfo()));
        die(json_encode($stm->errorInfo()));
    }

    return $dbConnection->lastInsertId();
}

function prepareAndSaveCVEConfiguration($cpe)
{
    $types = $GLOBALS['types'];

    $parsedCPE = parseCPE($cpe['cpe23Uri']);
    $libraryExist = getLibraryByVendorAndProduct($parsedCPE[3], $parsedCPE[4]);

    $tmp['cve_id'] = $cpe['cve_id'];
    $tmp['libraryId'] = $libraryExist ? $libraryExist['id'] : saveLibrary($parsedCPE[3], $parsedCPE[4]);
    $tmp['type'] = $parsedCPE[2] ? $types[$parsedCPE[2]] : $types['unrecognized'];
    $tmp['vendor'] = isset($parsedCPE[3]) ? str_replace('_', ' ', $parsedCPE[3]) : null;
    $tmp['product'] = isset($parsedCPE[4]) ? str_replace('_', ' ', $parsedCPE[4]) : null;
    $tmp['version'] = isset($parsedCPE[5]) ? $parsedCPE[5] : null;
    $tmp['module_name'] = isset($cpe['cpe23Uri']) ? $cpe['cpe23Uri'] : null;
    $tmp['versionEndIncluding'] = isset($cpe['versionEndIncluding']) ? $cpe['versionEndIncluding'] : null;
    $tmp['versionEndExcluding'] = isset($cpe['versionEndExcluding']) ? $cpe['versionEndExcluding'] : null;
    $tmp['versionStartIncluding'] = isset($cpe['versionStartIncluding']) ? $cpe['versionStartIncluding'] : null;
    $tmp['versionStartExcluding'] = isset($cpe['versionStartExcluding']) ? $cpe['versionStartExcluding'] : null;
    $tmp['vulnerable'] = isset($cpe['vulnerable']) ? ($cpe['vulnerable'] == "true" ? 1 : 0) : null;
    $tmp['source'] = NVD;

    saveCveConfiguration($tmp);
}

function saveCveConfiguration($cveConfiguration)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $sql = 'INSERT INTO cve_configurations (cve_id, type, vendor, product, version, module_name, library_id, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding, vulnerable, source)
            VALUES (:cve_id, :type, :vendor, :product, :version, :module_name, :library_id, :versionStartIncluding, :versionStartExcluding, :versionEndIncluding, :versionEndExcluding, :vulnerable, :source)';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(":cve_id", $cveConfiguration['cve_id'], \PDO::PARAM_INT);
    $stm->bindParam(":library_id", $cveConfiguration['libraryId'], \PDO::PARAM_INT);
    $stm->bindParam(":type", $cveConfiguration['type'], \PDO::PARAM_INT);
    $stm->bindParam(":vendor", $cveConfiguration['vendor'], \PDO::PARAM_STR);
    $stm->bindParam(":product", $cveConfiguration['product'], \PDO::PARAM_STR);
    $stm->bindParam(":version", $cveConfiguration['version'], \PDO::PARAM_STR);
    $stm->bindParam(":module_name", $cveConfiguration['module_name'], \PDO::PARAM_STR);
    $stm->bindParam(":versionStartIncluding", $cveConfiguration['versionStartIncluding'], \PDO::PARAM_STR);
    $stm->bindParam(":versionStartExcluding", $cveConfiguration['versionStartExcluding'], \PDO::PARAM_STR);
    $stm->bindParam(":versionEndIncluding", $cveConfiguration['versionEndIncluding'], \PDO::PARAM_STR);
    $stm->bindParam(":versionEndExcluding", $cveConfiguration['versionEndExcluding'], \PDO::PARAM_STR);
    $stm->bindParam(":vulnerable", $cveConfiguration['vulnerable'], \PDO::PARAM_INT);
    $stm->bindParam(":source", $cveConfiguration['source'], \PDO::PARAM_INT);
    //$stm->bindParam(":operator", $cveConfiguration['operator'], \PDO::PARAM_INT);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not save Vulnerability. Details: ' . json_encode($stm->errorInfo()));
        return false;
    }

    return true;
}

function saveCwe($cwe)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $sql = 'INSERT INTO cwes (uid, cwe)
            VALUES (UUID(), :cwe)';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(":cwe", $cwe, \PDO::PARAM_STR);

    if (!$stm->execute()) {
        $logger->error("[DB] Could not save CWE($cwe). Details: " . json_encode($stm->errorInfo()));
        return false;
    }

    return $dbConnection->lastInsertId();
}

function saveCweMatchForCve($cveId, $cwe)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $sql = 'INSERT IGNORE INTO cve_cwes (cve_id, cwe_id)
            VALUES (:cve, :cwe)';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(":cve", $cveId, \PDO::PARAM_INT);
    $stm->bindParam(":cwe", $cwe, \PDO::PARAM_STR);

    if (!$stm->execute()) {
        $logger->error("[DB] Could not save CWE($cwe) - CVE ID($cveId). Details: " . json_encode($stm->errorInfo()));
        return false;
    }

    return true;
}

function saveTitle($title)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $sql = 'INSERT INTO titles (uid, title)
            VALUES (UUID(), :title)';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(":title", $title, \PDO::PARAM_STR);

    if (!$stm->execute()) {
        $logger->error("[DB] Could not save title ($title). Details: " . json_encode($stm->errorInfo()));
        return false;
    }

    return $dbConnection->lastInsertId();
}

function getTitleByTitle($title)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $result = [];

    $sql = 'SELECT *
            FROM titles
            WHERE title = :title';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(':title', $title, \PDO::PARAM_STR);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not fetch title record!' . json_encode($stm->errorInfo()));
        return false;
    }

    while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {
        $result = $row;
    }

    return $result;
}

function saveLibraryWithPkg($vendor, $product, $pkg)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $time = time();

    $sql = 'INSERT IGNORE INTO libraries (vendor, product, pkg, created, updated)
            VALUES (:vendor, :product, :pkg, :created, :updated)';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(":vendor", $vendor, \PDO::PARAM_STR);
    $stm->bindParam(":product", $product, \PDO::PARAM_STR);
    $stm->bindParam(":pkg", $pkg, \PDO::PARAM_INT);
    $stm->bindParam(":created", $time, \PDO::PARAM_INT);
    $stm->bindParam(":updated", $time, \PDO::PARAM_INT);

    if (!$stm->execute()) {
        $logger->error("[DB] Could not save library ($pkg:$vendor/$product). Details: " . json_encode($stm->errorInfo()));
        return false;
    }

    return $dbConnection->lastInsertId();
}

function saveLibrary($vendor, $product)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $time = time();

    $sql = 'INSERT IGNORE INTO libraries (vendor, product, created, updated)
            VALUES (:vendor, :product, :created, :updated)';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(":vendor", $vendor, \PDO::PARAM_STR);
    $stm->bindParam(":product", $product, \PDO::PARAM_STR);
    $stm->bindParam(":created", $time, \PDO::PARAM_INT);
    $stm->bindParam(":updated", $time, \PDO::PARAM_INT);

    if (!$stm->execute()) {
        $logger->error("[DB] Could not save library ($vendor/$product). Details: " . json_encode($stm->errorInfo()));
        return false;
    }

    return $dbConnection->lastInsertId();
}

function saveCveReference($reference)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $sql = 'INSERT INTO cve_references (cve, url, `name`, refsource, tags)
            VALUES (:cve, :url, :name, :refsource, :tags)';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(":cve", $reference['cve'], \PDO::PARAM_INT);
    $stm->bindParam(":url", $reference['url'], \PDO::PARAM_STR);
    $stm->bindParam(":name", $reference['name'], \PDO::PARAM_STR);
    $stm->bindParam(":refsource", $reference['refsource'], \PDO::PARAM_STR);
    $stm->bindParam(":tags", $reference['tags'], \PDO::PARAM_STR);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not save Cve References. Details: ' . json_encode($stm->errorInfo()));
        return false;
    }

    return true;
}

function saveNpmReference($reference)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $sql = 'INSERT IGNORE INTO npm_references (npm_id, link, `name`, tag)
            VALUES (:npm_id, :link, :name, :tags)';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(":npm_id", $reference['npm_id'], \PDO::PARAM_INT);
    $stm->bindParam(":link", $reference['link'], \PDO::PARAM_STR);
    $stm->bindParam(":name", $reference['name'], \PDO::PARAM_STR);
    $stm->bindParam(":tags", $reference['tags'], \PDO::PARAM_STR);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not save Npm References. Details: ' . json_encode($stm->errorInfo()));
        return false;
    }

    return true;
}

function getCweByCwe($cwe)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $result = [];

    $sql = 'SELECT *
            FROM cwes
            WHERE cwe = :cwe';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(':cwe', $cwe, \PDO::PARAM_STR);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not fetch CWE record!' . json_encode($stm->errorInfo()));
        return false;
    }

    while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {
        $result = $row;
    }

    return $result;
}

function getCveByCveId($cve)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $result = [];

    $sql = 'SELECT *
            FROM cves
            WHERE cve = :cve';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(':cve', $cve, \PDO::PARAM_STR);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not fetch CVE record!' . json_encode($stm->errorInfo()));
        return false;
    }

    while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {
        $result = $row;
    }

    return $result;
}

function updateCveDetails($id, $cve)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $sql = 'UPDATE cves 
            SET v3Severity = :v3Severity,
                v2Severity = :v2Severity,
                v3VectorString = :v3VectorString,
                v2VectorString = :v2VectorString,
                v3BaseScore = :v3BaseScore,
                v2BaseScore = :v2BaseScore,
                v3ExploitabilityScore = :v3ExploitabilityScore,
                v2ExploitabilityScore = :v2ExploitabilityScore,
                v3ImpactScore = :v3ImpactScore,
                v2ImpactScore = :v2ImpactScore,  
                description = :description,
                created = :created, 
                updated = :updated
            WHERE id = :id';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(':id', $id, \PDO::PARAM_INT);
    $stm->bindParam(':v3Severity', $cve['v3Severity'], \PDO::PARAM_INT);
    $stm->bindParam(':v2Severity', $cve['v2Severity'], \PDO::PARAM_INT);
    $stm->bindParam(':v3VectorString', $cve['v3VectorString'], \PDO::PARAM_STR);
    $stm->bindParam(':v2VectorString', $cve['v2VectorString'], \PDO::PARAM_STR);
    $stm->bindParam(':v3BaseScore', $cve['v3BaseScore'], \PDO::PARAM_INT);
    $stm->bindParam(':v2BaseScore', $cve['v2BaseScore'], \PDO::PARAM_INT);
    $stm->bindParam(':v3ExploitabilityScore', $cve['v3ExploitabilityScore'], \PDO::PARAM_INT);
    $stm->bindParam(':v2ExploitabilityScore', $cve['v2ExploitabilityScore'], \PDO::PARAM_INT);
    $stm->bindParam(':v3ImpactScore', $cve['v3ImpactScore'], \PDO::PARAM_INT);
    $stm->bindParam(':v2ImpactScore', $cve['v2ImpactScore'], \PDO::PARAM_INT);
    $stm->bindParam(':description', $cve['description'], \PDO::PARAM_STR);
    $stm->bindParam(':created', $cve['created'], \PDO::PARAM_STR);
    $stm->bindParam(':updated', $cve['updated'], \PDO::PARAM_STR);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not update vulnerabilities!' . json_encode($stm->errorInfo()));
        return false;
    }

    return true;
}

function deleteVulnerabilitiesByCveId($cve)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $sql = 'DELETE FROM cve_configurations
            WHERE cve_id = :cve';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(':cve', $cve, \PDO::PARAM_INT);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not delete vulnerabilities!' . json_encode($stm->errorInfo()));
        return false;
    }

    return true;
}

function saveCVEReferences($cveId, $references)
{
    foreach ($references as $reference) {
        $refTmp = null;

        $refTmp['cve'] = $cveId;
        $refTmp['url'] = $reference['url'];
        $refTmp['name'] = $reference['name'];
        $refTmp['refsource'] = $reference['refsource'];
        $refTmp['tags'] = implode(', ', $reference['tags']);

        saveCveReference($refTmp);
    }
}

function deleteCveReferencesByCveId($cve)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $sql = 'DELETE FROM cve_references
            WHERE cve = :cve_id';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(':cve_id', $cve, \PDO::PARAM_INT);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not delete cve references!' . json_encode($stm->errorInfo()));
        return false;
    }

    return true;
}

function deleteNvdRecordById($id)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $sql = 'DELETE
            FROM nvd
            WHERE id = :id';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(':id', $id, \PDO::PARAM_INT);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not delete NVD record!' . json_encode($stm->errorInfo()));
        return false;
    }

    return true;
}

function getNpmRecordBySourceId($sourceId)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $issue = [];

    $logger->info('[DB] Getting NPM record by source id: ' . $sourceId);

    $sql = 'SELECT *
            FROM vulnerabilities
            WHERE sid = :sid';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(':sid', $sourceId, \PDO::PARAM_INT);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not fetch NPM record!' . json_encode($stm->errorInfo()));
        return false;
    }

    while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {
        $issue = $row;
    }

    return $issue;
}

function getLibraryByVendorAndProductAndPkg($vendor, $product, $pkg)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $library = [];

    $sql = 'SELECT *
            FROM libraries
            WHERE vendor = :vendor AND product = :product AND pkg = :pkg';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(':vendor', $vendor, \PDO::PARAM_STR);
    $stm->bindParam(':product', $product, \PDO::PARAM_STR);
    $stm->bindParam(':pkg', $pkg, \PDO::PARAM_INT);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not fetch library record!' . json_encode($stm->errorInfo()));
        return false;
    }

    while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {
        $library = $row;
    }

    return $library;
}

function getLibraryByProductAndPkg($product, $pkg)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $library = [];

    $logger->info('[DB] Getting library record by product and pkg');

    $sql = 'SELECT *
            FROM libraries
            WHERE product = :product AND pkg = :pkg';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(':product', $product, \PDO::PARAM_STR);
    $stm->bindParam(':pkg', $pkg, \PDO::PARAM_INT);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not fetch library record!' . json_encode($stm->errorInfo()));
        return false;
    }

    while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {
        $library = $row;
    }

    return $library;
}

function getLibraryByVendorAndProduct($vendor, $product)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $library = [];

    $sql = 'SELECT *
            FROM libraries
            WHERE vendor = :vendor AND product = :product';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(':vendor', $vendor, \PDO::PARAM_STR);
    $stm->bindParam(':product', $product, \PDO::PARAM_STR);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not fetch library record!' . json_encode($stm->errorInfo()));
        return false;
    }

    while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {
        $library = $row;
    }

    return $library;
}

function getNvdCount()
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $count = 0;

    $logger->info('[DB] Getting NVD record count');

    $sql = 'SELECT count(id) AS nvdCount
            FROM nvd';

    $stm = $dbConnection->prepare($sql);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not fetch NPM record!' . json_encode($stm->errorInfo()));
        return false;
    }

    while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {
        $count = $row['nvdCount'];
    }

    return $count;
}

function getNpmFoundBy($reportedName)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $logger->info('[DB] Getting NVD Found by');

    $sql = 'SELECT *
            FROM npm_found_by
            WHERE name = :name';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(":name", $reportedName, \PDO::PARAM_STR);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not fetch NPM Found by!' . json_encode($stm->errorInfo()));
        return false;
    }

    $foundBy = [];

    while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {
        $foundBy = $row;
    }

    return $foundBy;
}

function getNpmReportedBy($reportedName)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $logger->info('[DB] Getting NVD Reported by');

    $sql = 'SELECT *
            FROM npm_reported_by
            WHERE name = :name';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(":name", $reportedName, \PDO::PARAM_STR);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not fetch NPM Reported by!' . json_encode($stm->errorInfo()));
        return false;
    }

    $reportedBy = [];

    while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {
        $reportedBy = $row;
    }

    return $reportedBy;
}

function getNpmVulnerabilityByNpmId($npmId)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $logger->info('[DB] Getting NVD Reported by');

    $sql = 'SELECT *
            FROM npm_vulnerabilities
            WHERE npm_id = :npm_id';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(":npm_id", $npmId, \PDO::PARAM_INT);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not fetch NPM Vulnerability!' . json_encode($stm->errorInfo()));
        return false;
    }

    $vulnerability = [];

    while ($row = $stm->fetch(\PDO::FETCH_ASSOC)) {
        $vulnerability = $row;
    }

    return $vulnerability;
}

function saveNvdSummary($summary)
{
    $dbConnection = $GLOBALS['dbConnection'];

    $sql = 'INSERT INTO nvd_summaries (start,finish,countBefore,countAfter)
            VALUES (:start,:finish,:countBefore,:countAfter)';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(":start", $summary['start'], \PDO::PARAM_INT);
    $stm->bindParam(":finish", $summary['finish'], \PDO::PARAM_INT);
    $stm->bindParam(":countBefore", $summary['countBefore'], \PDO::PARAM_INT);
    $stm->bindParam(":countAfter", $summary['countAfter'], \PDO::PARAM_INT);

    if (!$stm->execute()) {
        return false;
    }

    return true;
}

function saveNpmFoundBy($id, $foundBy)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $sql = 'INSERT INTO npm_found_by (npm_id, link, name, email)
            VALUES (:npm_id, :link, :name, :email)';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(":npm_id", $id, \PDO::PARAM_INT);
    $stm->bindParam(":link", $foundBy['link'], \PDO::PARAM_STR);
    $stm->bindParam(":name", $foundBy['name'], \PDO::PARAM_STR);
    $stm->bindParam(":email", $foundBy['email'], \PDO::PARAM_STR);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not insert NPM Found by!' . json_encode($stm->errorInfo()));
        return false;
    }

    return $dbConnection->lastInsertId();
}

function saveNpmReportedBy($id, $reportedBy)
{
    $dbConnection = $GLOBALS['dbConnection'];
    $logger = $GLOBALS['logger'];

    $sql = 'INSERT INTO npm_reported_by (npm_id, link, name, email)
            VALUES (:npm_id, :link, :name, :email)';

    $stm = $dbConnection->prepare($sql);
    $stm->bindParam(":npm_id", $id, \PDO::PARAM_INT);
    $stm->bindParam(":link", $reportedBy['link'], \PDO::PARAM_STR);
    $stm->bindParam(":name", $reportedBy['name'], \PDO::PARAM_STR);
    $stm->bindParam(":email", $reportedBy['email'], \PDO::PARAM_STR);

    if (!$stm->execute()) {
        $logger->error('[DB] Could not insert NPM Reported by!' . json_encode($stm->errorInfo()));
        return false;
    }

    return $dbConnection->lastInsertId();
}

function parseNpmReference($referenceString)
{
    $references = [];

    $referenceString = str_replace('- ', '', $referenceString);
    $referenceString = str_replace('[', '', $referenceString);
    $referenceString = str_replace(')', '', $referenceString);

    $tmpReferences = explode("\n", $referenceString);

    foreach ($tmpReferences as $reference) {
        $exploded = explode('](', $reference);
        $tmp['name'] = $exploded[0];
        $tmp['link'] = $exploded[1];

        $references[] = $tmp;
    }

    return $references;
}

function parseCPE($cpe)
{
    return explode(':', $cpe);
}

function parseNpmModuleName($moduleName)
{
    $exploded = ['vendor' => null, 'product' => null];
    $moduleName = str_replace('@', '', $moduleName);

    if (strpos($moduleName, '/') !== false) {
        $tmp = explode('/', $moduleName);
        $exploded['vendor'] = $tmp[0];
        $exploded['product'] = $tmp[1];
    } else {
        $exploded['product'] = $moduleName;
    }

    return $exploded;
}

function gen_uuid()
{
    return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        // 32 bits for "time_low"
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),

        // 16 bits for "time_mid"
        mt_rand(0, 0xffff),

        // 16 bits for "time_hi_and_version",
        // four most significant bits holds version number 4
        mt_rand(0, 0x0fff) | 0x4000,

        // 16 bits, 8 bits for "clk_seq_hi_res",
        // 8 bits for "clk_seq_low",
        // two most significant bits holds zero and one for variant DCE1.1
        mt_rand(0, 0x3fff) | 0x8000,

        // 48 bits for "node"
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
}