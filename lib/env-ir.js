/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * tempo-e (Integrity Requirement) module
 * @public
 */
(function(global) {
	"use strict;"

	// Declaration
	EnvIR["prototype"]["constructor"] = EnvIR;   // EnvIR(value:string):object
	EnvIR["prototype"]["setValue"] = setValue;   // EnvIR#setValue(value:string):this
	EnvIR["prototype"]["getName"] = getName;     // EnvIR#getName(void):string
	EnvIR["prototype"]["getScore"] = getScore;   // EnvIR#getScore(void):number
	EnvIR["prototype"]["getVector"] = getVector; // EnvIR#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Integrity Requirement
	 * @public
	 */
	function EnvIR(value) {
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
	 * @return name of Integrity Requirement
	 * @public
	 */
	function getName() {
		return 'IR';
	}

	/**
	 * Method : get score
	 *
	 * @return score of Integrity Requirement
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
	 * @return vector of Integrity Requirement
	 * @public
	 */
	function getVector() {
		return this.getName() + ':' + this.value;
	}

	// Exports
	if (typeof module === "object" && "exports" in module) {
		module["exports"] = EnvIR;
	    return;
	}
	global["CVSS3_Environmental_IR"] = EnvIR;

})((this || 0).self || global);
