/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * base-i (Integrity Impact) module
 * @public
 */
(function(global) {
	"use strict;"

	// Declaration
	BaseI["prototype"]["constructor"] = BaseI;   // BaseI(value:string):object
	BaseI["prototype"]["setValue"] = setValue;   // BaseI#setValue(value:string):this
	BaseI["prototype"]["getName"] = getName;     // BaseI#getName(void):string
	BaseI["prototype"]["getScore"] = getScore;   // BaseI#getScore(void):number
	BaseI["prototype"]["getVector"] = getVector; // BaseI#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Integrity Impact
	 * @public
	 */
	function BaseI(value) {
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
	 * @return name of Integrity Impact
	 * @public
	 */
	function getName() {
		return 'I';
	}

	/**
	 * Method : get score
	 *
	 * @return score of Integrity Impact
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
	 * @return vector of Integrity Impact
	 * @public
	 */
	function getVector() {
		return this.getName() + ':' + this.value;
	}

	// Exports
	if ("process" in global) {
		module["exports"] = BaseI;
	}
	global["BaseI"] = BaseI;

})((this || 0).self || global);
