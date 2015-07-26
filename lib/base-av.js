/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * base-av (Attack Vector) module
 * @public
 */
(function(global) {
	"use strict;"

	// Declaration
	BaseAV["prototype"]["constructor"] = BaseAV;  // BaseAV(value:string):object
	BaseAV["prototype"]["setValue"] = setValue;   // BaseAV#setValue(value:string):this
	BaseAV["prototype"]["getName"] = getName;     // BaseAV#getName(void):string
	BaseAV["prototype"]["getScore"] = getScore;   // BaseAV#getScore(void):number
	BaseAV["prototype"]["getVector"] = getVector; // BaseAV#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : attack vector
	 * @public
	 */
	function BaseAV(value) {
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
		this.value = 'P';
		if (value == 'N' || value == 'A' || value == 'L') {
			this.value = value;
		}
		return this;
	}

	/**
	 * Method : get Name
	 *
	 * @return name of attack vector
	 * @public
	 */
	function getName() {
		return 'AV';
	}

	/**
	 * Method : get score
	 *
	 * @return score of attack vector
	 * @public
	 */
	function getScore() {
		if (this.value == 'N') { //Network
			return 0.85;
		} else if (this.value == 'A') { //Adjacent Network
			return 0.62;
		} else if (this.value == 'L') { //Local
			return 0.55;
		} else { //Physical
			return 0.20;
		}
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of attack vector
	 * @public
	 */
	function getVector() {
		return this.getName() + ':' + this.value;
	}

	// Exports
	if ("process" in global) {
		module["exports"] = BaseAV;
	}
	//global["baseAV"] = BaseAV;

})((this || 0).self || global);
