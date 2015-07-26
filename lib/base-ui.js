/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * base-ui (User Interaction) module
 * @public
 */
(function(global) {
	"use strict;"

	// Declaration
	BaseUI["prototype"]["constructor"] = BaseUI;  // BaseUI(value:string):object
	BaseUI["prototype"]["setValue"] = setValue;   // BaseUI#setValue(value:string):this
	BaseUI["prototype"]["getName"] = getName;     // BaseUI#getName(void):string
	BaseUI["prototype"]["getScore"] = getScore;   // BaseUI#getScore(void):number
	BaseUI["prototype"]["getVector"] = getVector; // BaseUI#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : User Interaction
	 * @public
	 */
	function BaseUI(value) {
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
		this.value = 'R';
		if (value == 'N') {
			this.value = value;
		}
		return this;
	}

	/**
	 * Method : get Name
	 *
	 * @return name of User Interaction
	 * @public
	 */
	function getName() {
		return 'UI';
	}

	/**
	 * Method : get score
	 *
	 * @return score of User Interaction
	 * @public
	 */
	function getScore() {
		if (this.value == 'N') { //None
			return 0.85;
		} else { //Required
			return 0.62;
		}
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of User Interaction
	 * @public
	 */
	function getVector() {
		return this.getName() + ':' + this.value;
	}

	// Exports
	if ("process" in global) {
		module["exports"] = BaseUI;
	}
	global["CVSS3_Base_UI"] = BaseUI;

})((this || 0).self || global);
