/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * tempo-e (Availability Requirement) module
 * @public
 */
(function(global) {
	"use strict;"

	// Declaration
	EnvAR["prototype"]["constructor"] = EnvAR;   // EnvAR(value:string):object
	EnvAR["prototype"]["setValue"] = setValue;   // EnvAR#setValue(value:string):this
	EnvAR["prototype"]["getName"] = getName;     // EnvAR#getName(void):string
	EnvAR["prototype"]["getScore"] = getScore;   // EnvAR#getScore(void):number
	EnvAR["prototype"]["getVector"] = getVector; // EnvAR#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Availability Requirement
	 * @public
	 */
	function EnvAR(value) {
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
	 * @return name of Availability Requirement
	 * @public
	 */
	function getName() {
		return 'AR';
	}

	/**
	 * Method : get score
	 *
	 * @return score of Availability Requirement
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
	 * @return vector of Availability Requirement
	 * @public
	 */
	function getVector() {
		return this.getName() + ':' + this.value;
	}

	// Exports
	if (typeof module === "object" && "exports" in module) {
		module["exports"] = EnvAR;
	    return;
	}
	global["CVSS3_Environmental_AR"] = EnvAR;

})((this || 0).self || global);
