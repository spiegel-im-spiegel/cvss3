/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * base-c (Confidentiality Impact) module
 * @public
 */
(function(global) {
	"use strict;"

	// Declaration
	BaseC["prototype"]["constructor"] = BaseC;   // BaseC(value:string):object
	BaseC["prototype"]["setValue"] = setValue;   // BaseC#setValue(value:string):this
	BaseC["prototype"]["getName"] = getName;     // BaseC#getName(void):string
	BaseC["prototype"]["getScore"] = getScore;   // BaseC#getScore(void):number
	BaseC["prototype"]["getVector"] = getVector; // BaseC#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Availability Impact
	 * @public
	 */
	function BaseC(value) {
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
		this.value = 'N';
		if (value == 'H' || value == 'L') {
			this.value = value;
		}
		return this;
	}

	/**
	 * Method : get Name
	 *
	 * @return name of Confidentiality Impact
	 * @public
	 */
	function getName() {
		return 'C';
	}

	/**
	 * Method : get score
	 *
	 * @return score of Confidentiality Impact
	 * @public
	 */
	function getScore() {
		if (this.value == 'H') { //High
			return 0.56;
		} else if (this.value == 'L') { //Low
			return 0.22;
		} else { //None
			return 0.0
		}
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of Confidentiality Impact
	 * @public
	 */
	function getVector() {
		return this.getName() + ':' + this.value;
	}

	// Exports
	if (typeof module === "object" && "exports" in module) {
		module["exports"] = BaseC;
	}
	global["CVSS3_Base_C"] = BaseC;

})((this || 0).self || global);
