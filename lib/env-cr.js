/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * tempo-e (Confidentiality Requirement) module
 * @public
 */
(function(global) {
	"use strict;"

	// Declaration
	EnvCR["prototype"]["constructor"] = EnvCR;   // EnvCR(value:string):object
	EnvCR["prototype"]["setValue"] = setValue;   // EnvCR#setValue(value:string):this
	EnvCR["prototype"]["getName"] = getName;     // EnvCR#getName(void):string
	EnvCR["prototype"]["getScore"] = getScore;   // EnvCR#getScore(void):number
	EnvCR["prototype"]["getVector"] = getVector; // EnvCR#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Confidentiality Requirement
	 * @public
	 */
	function EnvCR(value) {
		this.setValue(value);
	}

	/**
	 * Method : set value of metric
	 *
	 * @param {string} value : value of metric
	 * @return this object
	 * @public
	 */
	function setValue(value) {
		this.value = 'X';
		if (value == 'H' || value == 'M' || value == 'L') {
			this.value = value;
		}
		return this;
	}

	/**
	 * Method : get Name
	 *
	 * @return name of Confidentiality Requirement
	 * @public
	 */
	function getName() {
		return 'CR';
	}

	/**
	 * Method : get score
	 *
	 * @return score of Confidentiality Requirement
	 * @public
	 */
	function getScore() {
		if (this.value == 'H') { //High
			return 1.50;
		} else if (this.value == 'M') { //Medium
			return 1.00;
		} else if (this.value == 'L') { //Low
			return 0.50;
		} else { //Not Defined
			return 1.00
		}
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of Confidentiality Requirement
	 * @public
	 */
	function getVector() {
		return this.getName() + ':' + this.value;
	}

	// Exports
	if (typeof module === "object" && "exports" in module) {
		module["exports"] = EnvCR;
	    return;
	}
	global["CVSS3_Environmental_CR"] = EnvCR;

})((this || 0).self || global);
