/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * base-s (Scope) module
 * @public
 */
(function(global) {
	"use strict;"

	// Declaration
	BaseS["prototype"]["constructor"] = BaseS;   // BaseS(value:string):object
	BaseS["prototype"]["setValue"] = setValue;   // BaseS#setValue(value:string):this
	BaseS["prototype"]["getName"] = getName;     // BaseS#getName(void):string
	BaseS["prototype"]["getScore"] = getScore;   // BaseS#getScore(void):number
	BaseS["prototype"]["getVector"] = getVector; // BaseS#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : scope
	 * @public
	 */
	function BaseS(value) {
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
		this.value = 'U';
		if (value == 'C') {
			this.value = value;
		}
		return this;
	}

	/**
	 * Method : get Name
	 *
	 * @return name of scope
	 * @public
	 */
	function getName() {
		return 'S';
	}

	/**
	 * Method : get score (not used)
	 *
	 * @return score of scope
	 * @public
	 */
	function getScore() {
		return 0.0;
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of scope
	 * @public
	 */
	function getVector() {
		return this.getName() + ':' + this.value;
	}

	// Exports
	if ("process" in global) {
		module["exports"] = BaseS;
	}
	//global["BaseS"] = BaseS;

})((this || 0).self || global);
