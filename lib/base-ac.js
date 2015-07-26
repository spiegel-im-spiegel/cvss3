/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * base-ac (Attack Complexity) module
 * @public
 */
(function(global) {
	"use strict;"

	// Declaration
	BaseAC["prototype"]["constructor"] = BaseAC;  // BaseAC(value:string):object
	BaseAC["prototype"]["setValue"] = setValue; // BaseAC#setValue(value:string):this
	BaseAC["prototype"]["getName"] = getName;     // BaseAC#getName(void):string
	BaseAC["prototype"]["getScore"] = getScore;   // BaseAC#getScore(void):number
	BaseAC["prototype"]["getVector"] = getVector; // BaseAC#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Attack Complexity
	 * @public
	 */
	function BaseAC(value) {
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
		this.value = 'H';
		if (value == 'L') {
			this.value = value;
		}
		return this;
	}

	/**
	 * Method : get Name
	 *
	 * @return name of Attack Complexity
	 * @public
	 */
	function getName() {
		return 'AC';
	}

	/**
	 * Method : get score
	 *
	 * @return score of Attack Complexity
	 * @public
	 */
	function getScore() {
		if (this.value == 'L') { //Low
			return 0.77;
		} else { //High
			return 0.44;
		}
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of Attack Complexity
	 * @public
	 */
	function getVector() {
		return this.getName() + ':' + this.value;
	}

	// Exports
	if ("process" in global) {
		module["exports"] = BaseAC;
	}
	global["CVSS3_Base_AC"] = BaseAC;

})((this || 0).self || global);
