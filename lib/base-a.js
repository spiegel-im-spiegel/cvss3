/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * base-a (Availability Impact) module
 * @public
 */
(function(global) {
	"use strict;"

	// Declaration
	BaseA["prototype"]["constructor"] = BaseA;   // BaseA(value:string):object
	BaseA["prototype"]["setValue"] = setValue;   // BaseA#setValue(value:string):this
	BaseA["prototype"]["getName"] = getName;     // BaseA#getName(void):string
	BaseA["prototype"]["getScore"] = getScore;   // BaseA#getScore(void):number
	BaseA["prototype"]["getVector"] = getVector; // BaseA#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Availability Impact
	 * @public
	 */
	function BaseA(value) {
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
	 * @return name of Availability Impact
	 * @public
	 */
	function getName() {
		return 'A';
	}

	/**
	 * Method : get score
	 *
	 * @return score of Availability Impact
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
	 * @return vector of Availability Impact
	 * @public
	 */
	function getVector() {
		return this.getName() + ':' + this.value;
	}

	// Exports
	if (typeof module === "object" && "exports" in module) {
		module["exports"] = BaseA;
	    return;
	}
	global["CVSS3_Base_A"] = BaseA;

})((this || 0).self || global);
