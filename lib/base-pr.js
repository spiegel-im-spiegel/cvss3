/*!
 * JavaScript for CVSS (Common Vulnerability Scoring System) Version 3
 * These codes are licensed under CC0.
 * http://creativecommons.org/publicdomain/zero/1.0/deed.ja
 */

/**
 * base-pr (Privileges Required) module
 * @public
 */
(function(global) {
	"use strict;"

	// Declaration
	BasePR["prototype"]["constructor"] = BasePR;  // BasePR(value:string):object
	BasePR["prototype"]["setValue"] = setValue;   // BasePR#setValue(value:string):this
	BasePR["prototype"]["getName"] = getName;     // BasePR#getName(void):string
	BasePR["prototype"]["getScore"] = getScore;   // BasePR#getScore(s:object):number
	BasePR["prototype"]["getVector"] = getVector; // BasePR#getVector(void):string

	/**
	 * Constructor
	 *
	 * @param {string} value : Privileges Required
	 * @public
	 */
	function BasePR(value) {
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
		if (value == 'N' || value == 'L') {
			this.value = value;
		}
		return this;
	}

	/**
	 * Method : get Name
	 *
	 * @return name of Privileges Required
	 * @public
	 */
	function getName() {
		return 'PR';
	}

	/**
	 * Method : get score
	 *
	 * @param {boolean} change : true if Scope is "Changed"
	 * @return score of Privileges Required
	 * @public
	 */
	function getScore(change) {
		if (this.value == 'N') { //None
			return 0.85;
		} else if (this.value == 'L') { //Low
			if (change) {
				return 0.68;
			} else {
				return 0.62;
			}
		} else { //High
			if (change) {
				return 0.50;
			} else {
				return 0.27;
			}
		}
	}

	/**
	 * Method : get vector
	 *
	 * @return vector of Privileges Required
	 * @public
	 */
	function getVector() {
		return this.getName() + ':' + this.value;
	}

	/**
	 * Method : null or undefined (static)
	 *
	 * @param {object} obj : any object
	 * @return true if obj is null or undefined.
	 * @private
	 */
	function isNull(obj) {
		return ((typeof (obj) == 'undefined') || (obj == null));
	}

	// Exports
	if (typeof module === "object" && "exports" in module) {
		module["exports"] = BasePR;
	}
	global["CVSS3_Base_PR"] = BasePR;

})((this || 0).self || global);
