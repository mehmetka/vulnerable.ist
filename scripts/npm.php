<?php

require_once(__DIR__ . '/../vendor/autoload.php');
require(__DIR__ . '/lib.php');

use GuzzleHttp\Client;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;

date_default_timezone_set('Europe/Istanbul');
ini_set('memory_limit', '-1');

$settings = parse_ini_file(__DIR__ . '/../conf/conf.ini', true);

$logFileName = __DIR__ . '/../logs/npm.log';
if (!file_exists($logFileName)) {
    fopen($logFileName, "w");
}

$logger = new Logger('vulnerable.ist');
$logger->pushHandler(new StreamHandler($logFileName, Monolog\Logger::DEBUG));

$logger->info("# SCRIPT STARTED #");

try {
    $dbConnection = new PDO($settings['db']['driver'] . ":host=" . $settings['db']['host'] . ";dbname=" . $settings['db']['database'] . ";charset=" . $settings['db']['charset'], $settings['db']['user'], $settings['db']['password']);
} catch (Exception $e) {
    $logger->error('Database access problem: ' . $e->getMessage());
    die;
}

$guzzle = new Client([
    'verify' => false,
    'connect_timeout' => 6.66,
    'debug' => false
]);

$severities = [
    'critical' => 4,
    'high' => 3,
    'moderate' => 2,
    'low' => 1
];

for ($i = 1; $i < 74; $i++) {
    $link = 'https://registry.npmjs.org/-/npm/v1/security/advisories?perPage=20&page=' . $i;
    echo "Fetching => $link\n";
    $vulnerabilities = file_get_contents($link);
    $vulnerabilities = json_decode($vulnerabilities, true);

    foreach ($vulnerabilities['objects'] as $vulnerability) {

        $pkg = PKG_NPM;
        $libraryExist = [];
        $tmp['cve'] = null;

        $npmVulnerabilityExist = getNpmVulnerabilityByNpmId($vulnerability['id']);

        if ($npmVulnerabilityExist) {

            if ($npmVulnerabilityExist['updated'] === $vulnerability['updated']) {
                $logger->info("Nothing has changed {$vulnerability['id']}");
                continue;
            }

            // TODO update stuff

        }

        $tmp['npm_id'] = $vulnerability['id'];
        $title = utf8_encode($vulnerability['title']);
        $titleExist = getTitleByTitle($title);

        $tmp['title_id'] = $titleExist ? $titleExist['id'] : saveTitle($title);

        $moduleNameArray = parseNpmModuleName($vulnerability['module_name']);
        $tmp['module_name'] = $vulnerability['module_name'];
        $tmp['vendor'] = str_replace('_', '', $moduleNameArray['vendor']);
        $tmp['product'] = str_replace('_', '', $moduleNameArray['product']);

        $libraryExist = $moduleNameArray['vendor'] !== null ? getLibraryByVendorAndProductAndPkg($moduleNameArray['vendor'], $moduleNameArray['product'], PKG_NPM) : getLibraryByProductAndPkg($moduleNameArray['product'], PKG_NPM);
        $tmp['libraryId'] = $libraryExist ? $libraryExist['id'] : saveLibraryWithPkg($moduleNameArray['vendor'], $moduleNameArray['product'], PKG_NPM);

        $tmp['vulnerable_versions'] = $vulnerability['vulnerable_versions'];
        $tmp['patched_versions'] = $vulnerability['patched_versions'];
        $tmp['overview'] = $vulnerability['overview'];
        $tmp['recommendation'] = $vulnerability['recommendation'];
        $tmp['severity'] = $severities[$vulnerability['severity']];
        $tmp['created'] = $vulnerability['created'];
        $tmp['updated'] = $vulnerability['updated'];
        $tmp['deleted'] = $vulnerability['deleted'];
        $tmp['exploitability'] = $vulnerability['metadata']['exploitability'];

        $vulnerability['found_by'] = array_map("utf8_encode", $vulnerability['found_by']);
        $vulnerability['reported_by'] = array_map("utf8_encode", $vulnerability['reported_by']);

        if (isset($vulnerability['found_by']) && $vulnerability['found_by']['name'] != null) {
            $foundByExist = getNpmFoundBy($vulnerability['found_by']['name']);
            $tmp['found_by_id'] = $foundByExist ? $foundByExist['id'] : saveNpmFoundBy($tmp['npm_id'], $vulnerability['found_by']);
        }

        if (isset($vulnerability['reported_by']) && $vulnerability['reported_by']['name'] != null) {
            $reportedByExist = getNpmReportedBy($vulnerability['reported_by']['name']);
            $tmp['reported_by_id'] = $reportedByExist ? $reportedByExist['id'] : saveNpmReportedBy($tmp['npm_id'], $vulnerability['reported_by']);
        }

        $cweExist = getCweByCwe($vulnerability['cwe']);

        $tmp['cwe_id'] = $cweExist ? $cweExist['id'] : saveCwe($vulnerability['cwe']);

        if (count($vulnerability['cves'])) {
            $cve = $vulnerability['cves'][0];

            $cveDetail = getCveByCveId($cve);
            $tmp['cve_id'] = $cveDetail['id'];
        }

        if ($vulnerability['references']) {
            $references = parseNpmReference($vulnerability['references']);

            foreach ($references as $reference) {
                $reference['npm_id'] = $tmp['npm_id'];
                $reference['tags'] = null;
                saveNpmReference($reference);
            }
        }

        saveNPMVulnerability($tmp);
    }

}