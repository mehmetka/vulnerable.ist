CREATE TABLE `cve_configurations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `cve_id` int(11) NOT NULL,
  `type` int(11) NOT NULL,
  `vendor` varchar(255) COLLATE utf8mb4_bin NOT NULL,
  `product` varchar(255) COLLATE utf8mb4_bin NOT NULL,
  `version` varchar(255) COLLATE utf8mb4_bin NOT NULL,
  `module_name` varchar(255) COLLATE utf8mb4_bin NOT NULL,
  `library_id` int(11) NOT NULL,
  `versionStartIncluding` varchar(45) COLLATE utf8mb4_bin DEFAULT NULL,
  `versionStartExcluding` varchar(45) COLLATE utf8mb4_bin DEFAULT NULL,
  `versionEndIncluding` varchar(45) COLLATE utf8mb4_bin DEFAULT NULL,
  `versionEndExcluding` varchar(45) COLLATE utf8mb4_bin DEFAULT NULL,
  `vulnerable` int(11) NOT NULL,
  `source` int(11) NOT NULL,
  `operator` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  FULLTEXT KEY `fti_product` (`product`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE `cve_cwes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `cve_id` int(11) NOT NULL,
  `cwe_id` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE `cve_references` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `cve` int(11) NOT NULL,
  `url` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  `name` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  `refsource` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  `tags` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE `cves` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uid` varchar(255) COLLATE utf8mb4_bin NOT NULL,
  `cve` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  `v3Severity` int(11) DEFAULT NULL,
  `v2Severity` int(11) DEFAULT NULL,
  `v3VectorString` varchar(255) COLLATE utf8mb4_bin DEFAULT NULL,
  `v2VectorString` varchar(255) COLLATE utf8mb4_bin DEFAULT NULL,
  `v3BaseScore` varchar(255) COLLATE utf8mb4_bin DEFAULT NULL,
  `v2BaseScore` varchar(255) COLLATE utf8mb4_bin DEFAULT NULL,
  `v3ExploitabilityScore` varchar(255) COLLATE utf8mb4_bin DEFAULT NULL,
  `v2ExploitabilityScore` varchar(255) COLLATE utf8mb4_bin DEFAULT NULL,
  `v3ImpactScore` varchar(255) COLLATE utf8mb4_bin DEFAULT NULL,
  `v2ImpactScore` varchar(255) COLLATE utf8mb4_bin DEFAULT NULL,
  `description` mediumtext COLLATE utf8mb4_bin,
  `created` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  `updated` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE `cwes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uid` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  `cwe` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE `libraries` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vendor` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  `product` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  `pkg` int(11) NOT NULL,
  `created` int(11) NOT NULL,
  `updated` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE `npm_found_by` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `npm_id` int(11) NOT NULL,
  `link` varchar(255) COLLATE utf8mb4_bin NOT NULL,
  `name` varchar(255) COLLATE utf8mb4_bin NOT NULL,
  `email` varchar(255) COLLATE utf8mb4_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE `npm_references` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `npm_id` int(11) NOT NULL,
  `link` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  `name` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  `tag` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE `npm_reported_by` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `npm_id` int(11) NOT NULL,
  `link` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  `name` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  `email` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE `npm_vulnerabilities` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uid` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  `npm_id` int(11) NOT NULL,
  `title_id` int(11) NOT NULL,
  `vendor` varchar(255) COLLATE utf8mb4_bin NOT NULL,
  `product` varchar(255) COLLATE utf8mb4_bin NOT NULL,
  `module_name` varchar(255) COLLATE utf8mb4_bin NOT NULL,
  `library_id` int(11) NOT NULL,
  `cve_id` int(11) NOT NULL,
  `cwe_id` int(11) NOT NULL,
  `found_by_id` int(11) NOT NULL,
  `reported_by_id` int(11) NOT NULL,
  `severity` int(11) NOT NULL,
  `vulnerable_versions` varchar(255) COLLATE utf8mb4_bin NOT NULL,
  `patched_versions` varchar(255) COLLATE utf8mb4_bin NOT NULL,
  `exploitability` int(11) NOT NULL,
  `overview` varchar(255) COLLATE utf8mb4_bin NOT NULL,
  `recommendation` varchar(255) COLLATE utf8mb4_bin NOT NULL,
  `created` varchar(255) COLLATE utf8mb4_bin DEFAULT NULL,
  `updated` varchar(255) COLLATE utf8mb4_bin DEFAULT NULL,
  `deleted` varchar(255) COLLATE utf8mb4_bin DEFAULT NULL,
  PRIMARY KEY (`id`),
  FULLTEXT KEY `fulltext_npmv_product` (`product`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE `nvd_summaries` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `start` int(11) NOT NULL,
  `finish` int(11) NOT NULL,
  `countBefore` int(11) NOT NULL,
  `countAfter` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE `search_params` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `query` varchar(100) COLLATE utf8mb4_bin NOT NULL,
  `created` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE `titles` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uid` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  `title` varchar(45) COLLATE utf8mb4_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
