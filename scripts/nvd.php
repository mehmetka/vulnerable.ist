<?php

require_once(__DIR__ . '/../vendor/autoload.php');
require(__DIR__ . '/lib.php');

use GuzzleHttp\Client;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;

date_default_timezone_set('Europe/Istanbul');
ini_set('memory_limit', '-1');

$settings = parse_ini_file(__DIR__ . '/../conf/conf.ini', true);

$logFileName = __DIR__ . '/../logs/nvd.log';
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

$versions = [
    '2002',
    '2003',
    '2004',
    '2005',
    '2006',
    '2007',
    '2008',
    '2009',
    '2010',
    '2011',
    '2012',
    '2013',
    '2014',
    '2015',
    '2016',
    '2017',
    '2018',
    '2019',
    '2020',
    '2021',
    'recent',
    'modified'
];

$fileName = __DIR__ . '/summary.json';
fopen($fileName, "w");
$summary['start'] = date('Y-m-d H:i:s', time());
file_put_contents($fileName, json_encode($summary));

foreach ($versions as $version) {

    $baseLink = 'https://nvd.nist.gov/feeds/json/cve/1.1/';
    $base = "nvdcve-1.1-$version";
    $json = $base . '.json';
    $zip = $json . '.zip';
    $meta = $base . '.meta';
    $link = $baseLink . $zip;
    $file = __DIR__ . '/../nvd/' . $zip;
    $metadataFile = __DIR__ . '/../nvd/' . $meta;

    # Meta part
    try {
        $metadata = file_get_contents($baseLink . $meta);
    } catch (Exception $exception) {
        die($exception->getMessage());
    }

    $metadataArray = explode("\n", $metadata);

    if (file_exists($metadataFile) && filesize($metadataFile) != 0) {
        $tmp = file_get_contents($metadataFile);
        $tmp = explode("\n", $tmp);

        if ($tmp[0] === $metadataArray[0] && $tmp[4] === $metadataArray[4]) {
            echo "No update for $base, skipping\n";
            continue;
        }

    }

    fopen($metadataFile, "w");
    file_put_contents($metadataFile, $metadata);

    echo "Fetching => $link\n";
    downloadFile($link, $file);

    echo "Unzipping $file\n";
    $zipArchive = new ZipArchive();
    $result = $zipArchive->open($file);
    if ($result === true) {
        $zipArchive->extractTo(__DIR__ . '/../nvd');
        $zipArchive->close();
        echo "Successfully downloaded and unzipped the file " . __DIR__ . '/../nvd/' . $json . PHP_EOL;
    }

    $vulnerabilities = file_get_contents(__DIR__ . '/../nvd/' . $json);
    $vulnerabilities = json_decode($vulnerabilities, true);
    echo "Starting to parse operations. CVE Count: {$vulnerabilities['CVE_data_numberOfCVEs']}\n";

    foreach ($vulnerabilities['CVE_Items'] as $vulnerability) {

        $cveExist = getCveByCveId($vulnerability['cve']['CVE_data_meta']['ID']);

        $cve['cve'] = $vulnerability['cve']['CVE_data_meta']['ID'];
        $cve['description'] = $vulnerability['cve']['description']['description_data'][0]['value'];
        $cve['created'] = $vulnerability['publishedDate'];
        $cve['updated'] = $vulnerability['lastModifiedDate'];
        $cve['v3Severity'] = $severities[$vulnerability['impact']['baseMetricV3']['cvssV3']['baseSeverity']];
        $cve['v3VectorString'] = $vulnerability['impact']['baseMetricV3']['cvssV3']['vectorString'];
        $cve['v3BaseScore'] = $vulnerability['impact']['baseMetricV3']['cvssV3']['baseScore'];
        $cve['v3ExploitabilityScore'] = $vulnerability['impact']['baseMetricV3']['exploitabilityScore'];
        $cve['v3ImpactScore'] = $vulnerability['impact']['baseMetricV3']['impactScore'];
        $cve['v2Severity'] = $severities[$vulnerability['impact']['baseMetricV2']['severity']];
        $cve['v2VectorString'] = $vulnerability['impact']['baseMetricV2']['cvssV2']['vectorString'];
        $cve['v2BaseScore'] = $vulnerability['impact']['baseMetricV2']['cvssV2']['baseScore'];
        $cve['v2ExploitabilityScore'] = $vulnerability['impact']['baseMetricV2']['exploitabilityScore'];
        $cve['v2ImpactScore'] = $vulnerability['impact']['baseMetricV2']['impactScore'];

        if ($cveExist) {

            if ($cveExist['updated'] == $vulnerability['lastModifiedDate']) {
                continue;
            }

            $cveId = $cveExist['id'];
            updateCveDetails($cveId, $cve);
            deleteVulnerabilitiesByCveId($cveId);
            deleteCveReferencesByCveId($cveId);

        } else {
            $cveId = saveCve($cve);
        }

        saveCVEReferences($cveId, $vulnerability['cve']['references']['reference_data']);

        if (isset($vulnerability['cve']['problemtype']['problemtype_data'][0]['description'][0]['value'])) {

            $cweExist = getCweByCwe($vulnerability['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']);

            if ($cweExist) {
                saveCweMatchForCve($cveId, $cweExist['id']);
            } else {
                $cweId = saveCwe($vulnerability['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']);
                saveCweMatchForCve($cveId, $cweId);
            }

        }

        if (isset($vulnerability['configurations']['nodes'][0]['cpe_match'])) {

            foreach ($vulnerability['configurations']['nodes'] as $node) {

                if (isset($node['cpe_match'])) {

                    if (count($node['cpe_match'])) {

                        foreach ($node['cpe_match'] as $cpe) {
                            $cpe['cve_id'] = $cveId;
                            prepareAndSaveCVEConfiguration($cpe);
                        }

                    }

                } elseif ($node['children']) {

                    foreach ($node['children'] as $child) {

                        if (count($child['cpe_match'])) {

                            foreach ($child['cpe_match'] as $cpe) {
                                $cpe['cve_id'] = $cveId;
                                prepareAndSaveCVEConfiguration($cpe);
                            }

                        }

                    }

                }

            }

        } elseif (isset($vulnerability['configurations']['nodes'][0]['children'])) {

            foreach ($vulnerability['configurations']['nodes'][0]['children'] as $child) {

                if (count($child['cpe_match'])) {

                    foreach ($child['cpe_match'] as $cpe) {
                        $cpe['cve_id'] = $cveId;
                        prepareAndSaveCVEConfiguration($cpe);
                    }

                }

            }

        }
    }

    if (file_exists($file)) {
        echo "Deleting $file\n";
        unlink($file);
    }

}

fopen($fileName, "w");
$summary['finish'] = date('Y-m-d H:i:s', time());
file_put_contents($fileName, json_encode($summary));