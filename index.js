/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * cvss3 (Common Vulnerability Scoring System Version 3) module
 * @public
 */
(function(global) {
	"use strict;"

	// Declaration
	CVSS3["BaseMetrics"] = require('./lib/base'); // CVSS3.BaseMetrics(any):object

	/**
	 * Constructor
	 *
	 * @public
	 */
	function CVSS3() { }

	// Exports
	if ("process" in global) {
		module["exports"] = CVSS3;
	}
	global["CVSS3"] = CVSS3;

})((this || 0).self || global);
